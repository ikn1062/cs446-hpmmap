/* Copyright (c) 2007, Sandia National Laboratories */
/* Modified by Jack Lange, 2012 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/log2.h>

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/version.h>

#include "buddy.h"
#include "hpmmap.h"
#include "../interface.h"

/**
 * Converts a block address to its block index in the specified buddy allocator.
 * A block's index is used to find the block's tag bit, mp->tag_bits[block_id].
 */
static unsigned long
block_to_id(struct buddy_mempool * mp, 
            struct block         * block)
{
    unsigned long block_id =
        ((unsigned long)__pa(block) - mp->base_addr) >> mp->zone->min_order;
    BUG_ON(block_id >= mp->num_blocks);
    return block_id;
}


/**
 * Marks a block as free by setting its tag bit to one.
 */
static void
mark_available(struct buddy_mempool * mp, 
               struct block         * block)
{
    __set_bit(block_to_id(mp, block), mp->tag_bits);
}


/**
 * Marks a block as allocated by setting its tag bit to zero.
 */
static void
mark_allocated(struct buddy_mempool * mp, 
               struct block         * block)
{
    __clear_bit(block_to_id(mp, block), mp->tag_bits);
}


/**
 * Returns true if block is free, false if it is allocated.
 */
static int
is_available(struct buddy_mempool * mp, 
             struct block         * block)
{
    return test_bit(block_to_id(mp, block), mp->tag_bits);
}


/**
 * Returns the address of the block's buddy block.
 */
static void *
find_buddy(struct buddy_mempool * mp, 
           struct block         * block, 
           unsigned long          order)
{
    unsigned long _block;
    unsigned long _buddy;

    BUG_ON((unsigned long)__pa(block) < mp->base_addr);

    /* Fixup block address to be zero-relative */
    _block = (unsigned long)__pa(block) - mp->base_addr;

    /* Calculate buddy in zero-relative space */
    _buddy = _block ^ (1UL << order);

    /* Return the buddy's address */
    return (void *)(_buddy + __va(mp->base_addr));
}


static inline uintptr_t 
pool_end_addr(struct buddy_mempool * pool) 
{
    return pool->base_addr + (1UL << pool->pool_order);
}


static struct buddy_mempool * 
find_mempool(struct buddy_memzone * zone, 
             uintptr_t              addr) 
{
    struct rb_node       * n    = zone->mempools.rb_node;
    struct buddy_mempool * pool = NULL;

    while (n) {
        pool = rb_entry(n, struct buddy_mempool, tree_node);

        if (addr < pool->base_addr) {
            n = n->rb_left;
        } else if (addr >= pool_end_addr(pool)) {
            n = n->rb_right;
        } else {
            return pool;
        }
    }

    return NULL;
}


static int 
insert_mempool(struct buddy_memzone * zone, 
               struct buddy_mempool * pool)
{
    struct rb_node ** p             = &(zone->mempools.rb_node);
    struct rb_node * parent         = NULL;
    struct buddy_mempool * tmp_pool = NULL;

    while (*p) {
        parent  = *p;
        tmp_pool = rb_entry(parent, struct buddy_mempool, tree_node);

        if (pool_end_addr(pool) <= tmp_pool->base_addr) {
            p = &(*p)->rb_left;
        } else if (pool->base_addr >= pool_end_addr(tmp_pool)) {
            p = &(*p)->rb_right;
        } else {
            return -1;
        }
    }

    rb_link_node(&(pool->tree_node), parent, p);  
    rb_insert_color(&(pool->tree_node), &(zone->mempools));
    zone->num_pools++;

    return 0;
}





/* This adds a pool of a given size to a buddy allocated zone
*/

int 
buddy_add_pool(struct buddy_memzone * zone, 
               unsigned long          base_addr, 
               unsigned long          pool_order) 
{
    struct buddy_mempool * mp = NULL;
    unsigned long flags       = 0;
    int ret                   = 0;

    if (pool_order > zone->max_order) {
        PrintError("Pool order size is larger than max allowable zone size (pool_order=%lu) (max_order=%lu)\n", 
           pool_order, zone->max_order);
        return -1;
    } else if (pool_order < zone->min_order) {
        PrintError("Pool order is smaller than min allowable zone size (pool_order=%lu) (min_order=%lu)\n", 
           pool_order, zone->min_order);
        return -1;
    }

    mp = kmalloc_node(sizeof(struct buddy_mempool), GFP_KERNEL, zone->node_id);

    if (IS_ERR(mp)) {
        PrintError("Could not allocate mempool\n");
        return -1;
    }

    mp->base_addr       = base_addr;
    mp->pool_order      = pool_order;
    mp->zone            = zone;
    mp->num_free_blocks = 0;

    /* Allocate a bitmap with 1 bit per minimum-sized block */
    mp->num_blocks = (1UL << pool_order) / (1UL << zone->min_order);

    mp->tag_bits   = kmalloc_node(
                  BITS_TO_LONGS(mp->num_blocks) * sizeof(long), GFP_KERNEL, zone->node_id
                  );

    /* Initially mark all minimum-sized blocks as allocated */
    bitmap_zero(mp->tag_bits, mp->num_blocks);

    spin_lock_irqsave(&(zone->lock), flags);
    {
        ret = insert_mempool(zone, mp);
    }
    spin_unlock_irqrestore(&(zone->lock), flags);

    if (ret == -1) {
        PrintError("Could not insert mempool into zone\n");
        kfree(mp->tag_bits);
        kfree(mp);

        return -1;
    }

    buddy_free(zone, base_addr, pool_order);

    return 0;
}



/** 
 * Removes a mempool from a zone, 
 * assumes the zone lock is already held 
 */

static int
__buddy_remove_mempool(struct buddy_memzone * zone, 
                       struct buddy_mempool * pool, 
                       unsigned char          force) 
{
    struct block * block = NULL;

    if (pool->num_free_blocks != pool->num_blocks) {
        PrintError("Trying to remove an in use memory pool\n");
        return -1;
    }


    block = (struct block *)__va(pool->base_addr);

    list_del(&(block->link));
    rb_erase(&(pool->tree_node), &(zone->mempools));

    kfree(pool->tag_bits);
    kfree(pool);

    zone->num_pools--;

    return 0;
}

int 
buddy_remove_pool(struct buddy_memzone * zone,
                  unsigned long          base_addr, 
                  unsigned char          force) 
{
    struct buddy_mempool * pool = NULL;
    unsigned long flags         = 0;
    int ret                     = 0;


    spin_lock_irqsave(&(zone->lock), flags);    
    {
        pool = find_mempool(zone, base_addr);
        
        if (pool == NULL) {
            spin_unlock_irqrestore(&(zone->lock), flags);
            PrintError("Could not find mempool with base address (%p)\n", (void *)base_addr);
            return -1;
        }
        
        ret = __buddy_remove_mempool(zone, pool, force);
    }
    spin_unlock_irqrestore(&(zone->lock), flags);

    return ret;
}

int 
buddy_remove_memory(struct buddy_memzone * zone, 
                    unsigned long          size, 
                    unsigned long        * base_addr)
{
    unsigned long flags = 0;
    int ret             = -1;
    int order           = 0;

    order = get_order(size) + PAGE_SHIFT;

    spin_lock_irqsave(&(zone->lock), flags);
    {
        struct rb_node       * node = rb_first(&(zone->mempools));
        struct buddy_mempool * pool = NULL;

        while (node) {
            pool = rb_entry(node, struct buddy_mempool, tree_node);
    
            if (pool->pool_order == order) {

                ret = __buddy_remove_mempool(zone, pool, 0);

                if (ret == 0) {
                    *base_addr = pool->base_addr;
                    break;
                }
            }

            node = rb_next(node);
        }
    }
    spin_unlock_irqrestore(&(zone->lock), flags);

    return ret;
}



/**
 * Allocates a block of memory of the requested size (2^order bytes).
 *
 * Arguments:
 *       [IN] zone:     Buddy system memory zone.
 *       [IN] order:    Block size to allocate (2^order bytes).
 *
 * Returns:
 *       Success: Pointer to the start of the allocated memory block.
 *       Failure: NULL
 */
uintptr_t
buddy_alloc(struct buddy_memzone * zone, 
            unsigned long          order)
{
    struct buddy_mempool * mp  = NULL;
    struct list_head * list    = NULL;
    struct block * block       = NULL;
    struct block * buddy_block = NULL;
    unsigned long flags        = 0;
    unsigned long j            = 0;

    BUG_ON(zone == NULL);
    BUG_ON(order > zone->max_order);

    /* Fixup requested order to be at least the minimum supported */
    if (order < zone->min_order) {
        order = zone->min_order;
    }

    spin_lock_irqsave(&(zone->lock), flags);

    for (j = order; j <= zone->max_order; j++) {

        /* Try to allocate the first block in the order j list */
        list = &zone->avail[j];

        if (list_empty(list)) {
            continue;
        }

        block = list_entry(list->next, struct block, link);
        list_del(&block->link);

        mp = block->mp;

        mark_allocated(mp, block);

        /*
           spin_unlock_irqrestore(&(zone->lock), flags);
           return 0;
           */

        /* Trim if a higher order block than necessary was allocated */
        while (j > order) {
            --j;
            buddy_block        = (struct block *)((unsigned long)block + (1UL << j));
            buddy_block->mp    = mp;
            buddy_block->order = j;
            mark_available(mp, buddy_block);
            list_add(&(buddy_block->link), &(zone->avail[j]));
        }

        mp->num_free_blocks -= (1UL << (order - zone->min_order));

        spin_unlock_irqrestore(&(zone->lock), flags);

        return __pa(block);
    }

    spin_unlock_irqrestore(&(zone->lock), flags);

    return (uintptr_t)NULL;
}

/**
 * Determines number of bytes of memory that can be allocated
 *
 * Arguments:
 *       [IN] zone:     Buddy system memory zone.
 *
 * Returns: total number of bytes
 */
unsigned long long
buddy_check(struct buddy_memzone * zone)
{
    unsigned long i          = 0;
    unsigned long flags      = 0;
    unsigned long num_blocks = 0;
    unsigned long long bytes = 0;
    struct list_head * entry = NULL;

    BUG_ON(zone == NULL);

    spin_lock_irqsave(&(zone->lock), flags);
    {
        for (i = zone->min_order; i <= zone->max_order; i++) {
            /* Count the number of memory blocks in the list */
            num_blocks = 0;

            list_for_each(entry, &zone->avail[i]) {
                ++num_blocks;
            }

            bytes += (num_blocks * (1 << i));
        }
    }
    spin_unlock_irqrestore(&(zone->lock), flags);
    return bytes;
}

/**
 * Returns a block of memory to the buddy system memory allocator.
 */
void
buddy_free(struct buddy_memzone * zone,
           uintptr_t              addr,
           unsigned long          order) 
{
    struct block* block         = NULL;
    struct buddy_mempool * pool = NULL;
    unsigned long flags         = 0;

    BUG_ON(zone == NULL);
    BUG_ON(order > zone->max_order);

    /* Fixup requested order to be at least the minimum supported */
    if (order < zone->min_order) {
        order = zone->min_order;
    }

    spin_lock_irqsave(&(zone->lock), flags);

    pool = find_mempool(zone, addr);

    if ((pool == NULL) || (order > pool->pool_order)) {
        PrintError("Attempted to free an invalid page address (%p)\n", (void *)addr);
        spin_unlock_irqrestore(&(zone->lock), flags);
        return;
    }


    /* Overlay block structure on the memory block being freed */
    block = (struct block *) __va(addr);

    if (is_available(pool, block)) {
        PrintError("Freeing an available block\n");
        spin_unlock_irqrestore(&(zone->lock), flags);
        return;
    }

    pool->num_free_blocks += (1UL << (order - zone->min_order));

    /* Coalesce as much as possible with adjacent free buddy blocks */
    while (order < pool->pool_order) {
        /* Determine our buddy block's address */
        struct block * buddy = find_buddy(pool, block, order);

        /* Make sure buddy is available and has the same size as us */
        if (!is_available(pool, buddy)) {
            break;
        }

        if (is_available(pool, buddy) && (buddy->order != order)) {
            break;
        }

        /* OK, we're good to go... buddy merge! */
        list_del(&buddy->link);
        if (buddy < block) {
            block = buddy;
        }

        ++order;
        block->order = order;
    }

    /* Add the (possibly coalesced) block to the appropriate free list */
    block->order = order;
    block->mp    = pool;
    mark_available(pool, block);
    list_add(&(block->link), &(zone->avail[order]));

    spin_unlock_irqrestore(&(zone->lock), flags);
}

static void
seq_format_mempool_str(struct seq_file      * s, 
                       struct buddy_mempool * pool, 
                       unsigned long long     min_order)
{
    unsigned long free_bytes  = 0;
    int format_shift          = 0;
    int free_format_shift     = 0;

    char format_buf[3];
    char free_format_buf[3];

    memset(format_buf, 0, sizeof(format_buf));
    memset(free_format_buf, 0, sizeof(free_format_buf));

    if (pool->pool_order >= 30) {
        format_shift = 30;
        strncpy(format_buf, "GB", 2);
    } else if (pool->pool_order >= 20) {
        format_shift = 20;
        strncpy(format_buf, "MB", 2);
    } else if (pool->pool_order >= 10) {
        format_shift = 10;
        strncpy(format_buf, "KB", 2);
    } else {
        format_shift = 0;
        strncpy(format_buf, "B", 1);
    }
    free_bytes = pool->num_free_blocks << min_order;

    if (free_bytes >= (1LLU << 30)) {
        free_format_shift = 30;
        strncpy(free_format_buf, "GB", 2);
    } else if (free_bytes >= (1LLU << 20)) {
        free_format_shift = 20;
        strncpy(free_format_buf, "MB", 2);
    } else if (free_bytes >= (1LLU << 10)) {
        free_format_shift = 10;
        strncpy(free_format_buf, "KB", 2);
    } else {
        free_format_shift = 0;
        strncpy(free_format_buf, "B", 1);
    }

    seq_printf(s, "    Base Addr=%p, order=%lu, size=%lu%s, free=%lu%s\n", 
        (void *)pool->base_addr,
        pool->pool_order, 
        (1UL << (pool->pool_order - format_shift)), 
        format_buf,
        (free_bytes >> free_format_shift), 
        free_format_buf
    );

}


/**
 * Dumps the state of a buddy system memory allocator object to the console.
 */
static int 
zone_mem_show(struct seq_file * s, 
              void            * v)
{
    struct buddy_memzone * zone = s->private;
    struct list_head * entry    = NULL;
    unsigned long num_blocks    = 0;
    unsigned long flags         = 0;
    unsigned long i             = 0;

    if (!zone) {
        seq_printf(s, "Null Zone Pointer!!\n");
        return 0;
    }

    seq_printf(s, "DUMP OF BUDDY MEMORY ZONE:\n");
    seq_printf(s, "  Zone Max Order=%lu, Min Order=%lu\n", 
           zone->max_order, zone->min_order);

    spin_lock_irqsave(&(zone->lock), flags);

    for (i = zone->min_order; i <= zone->max_order; i++) {

        /* Count the number of memory blocks in the list */
        num_blocks = 0;

        list_for_each(entry, &zone->avail[i]) {
            ++num_blocks;
        }

        seq_printf(s, "  order %2lu: %lu free blocks\n", i, num_blocks);
    }


    seq_printf(s, " %lu memory pools\n", zone->num_pools);
    // list pools in zone
    {
        struct rb_node * node       = rb_first(&(zone->mempools));
        struct buddy_mempool * pool = NULL;

        while (node) {
            pool = rb_entry(node, struct buddy_mempool, tree_node);

            seq_format_mempool_str(s, pool, zone->min_order);

            node = rb_next(node);
        }
    }

    spin_unlock_irqrestore(&(zone->lock), flags);

    return 0;
}


static int
zone_proc_open(struct inode * inode, 
               struct file  * filp) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    return single_open(filp, zone_mem_show, PDE(inode)->data);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5,17,0)
    return single_open(filp, zone_mem_show, PDE_DATA(inode));
#else 
    return single_open(filp, zone_mem_show, pde_data(inode));
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
static struct file_operations 
zone_proc_ops =
{
    .owner   = THIS_MODULE,
    .open    = zone_proc_open, 
    .read    = seq_read,
    .llseek  = seq_lseek, 
    .release = single_release,
};
#else
static struct proc_ops 
zone_proc_ops =
{
    .proc_open    = zone_proc_open, 
    .proc_read    = seq_read,
    .proc_lseek  = seq_lseek, 
    .proc_release = single_release,
};
#endif

void 
buddy_deinit(struct buddy_memzone  * zone, 
             struct proc_dir_entry * parent)
{
    unsigned long flags = 0;

    spin_lock_irqsave(&(zone->lock), flags);

    // for each pool, free it
    {   
        struct rb_node       * node = rb_first(&(zone->mempools));
        struct buddy_mempool * pool = NULL;

        while (node) {
            pool = rb_entry(node, struct buddy_mempool, tree_node);
            __buddy_remove_mempool(zone, pool, 0);
            node = rb_next(node);
        }
    }   


    spin_unlock_irqrestore(&(zone->lock), flags);

    {
        char proc_file_name[128];
        memset(proc_file_name, 0, 128);

        snprintf(proc_file_name, 128, "zone%d", zone->node_id);

        remove_proc_entry(proc_file_name, parent);
    }


    kfree(zone->avail);
    kfree(zone);

    return;
}



/**
 * Initializes a buddy system memory allocator object.
 *
 * Arguments:
 *       [IN] base_addr:   Base address of the memory pool.
 *       [IN] pool_order:  Size of the memory pool (2^pool_order bytes).
 *       [IN] min_order:   Minimum allocatable block size (2^min_order bytes).
 *       [IN] parent_proc: proc_directory of parent node.
 *
 * Returns:
 *       Success: Pointer to an initialized buddy system memory allocator.
 *       Failure: NULL
 *
 * NOTE: The min_order argument is provided as an optimization. Since one tag
 *       bit is required for each minimum-sized block, large memory pools that
 *       allow order 0 allocations will use large amounts of memory. Specifying
 *       a min_order of 5 (32 bytes), for example, reduces the number of tag
 *       bits by 32x.
 */
struct buddy_memzone *
buddy_init(unsigned long           max_order,
           unsigned long           min_order,
           unsigned int            node_id,
           struct proc_dir_entry * parent)
{
    struct buddy_memzone * zone = NULL;
    unsigned long  i            = 0;

    PrintDebug("Initializing Memory zone with up to %lu bit blocks on Node %d\n", max_order, node_id);

    /* Smallest block size must be big enough to hold a block structure */
    if ((1UL << min_order) < sizeof(struct block))
        min_order = ilog2( roundup_pow_of_two(sizeof(struct block)) );

    /* The minimum block order must be smaller than the pool order */
    if (min_order > max_order)
        return NULL;

    zone = kmalloc_node(sizeof(struct buddy_memzone), GFP_KERNEL, node_id);

    if (IS_ERR(zone)) {
        PrintError("Could not allocate memzone\n");
        return NULL;
    }

    memset(zone, 0, sizeof(struct buddy_memzone));

    zone->max_order = max_order;
    zone->min_order = min_order;
    zone->node_id   = node_id;

    /* Allocate a list for every order up to the maximum allowed order */
    zone->avail     = kmalloc_node((max_order + 1) * sizeof(struct list_head), GFP_KERNEL, zone->node_id);

    /* Initially all lists are empty */
    for (i = 0; i <= max_order; i++) {
        INIT_LIST_HEAD(&zone->avail[i]);
    }

    spin_lock_init(&(zone->lock));

    zone->mempools.rb_node = NULL;

    {
        struct proc_dir_entry * zone_entry = NULL;
        char proc_file_name[128];
    
        memset(proc_file_name, 0, 128);
        snprintf(proc_file_name, 128, "zone%d", zone->node_id);

        zone_entry = proc_create_data(proc_file_name, 0444, parent, &zone_proc_ops, (void *)zone);
        if (!zone_entry) {
            printk(KERN_ERR "Error creating memory zone proc file\n");
        }

    }

    return zone;
}
