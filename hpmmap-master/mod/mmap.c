#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include <linux/version.h>
#include <asm/uaccess.h>

#include <asm/tlb.h>

#include "mmap.h"
#include "mapper.h"
#include "hpmmap.h"
#include "util-hashtable.h"
#include "pgtables.h"
#include "override.h"
#include "mm.h"


#define HPMMAP_PAGE_PROT (PROT_READ | PROT_WRITE | PROT_EXEC)

/* Prototype for original brk definition */ 
static int
(*original_brk)(unsigned long) = NULL; 

/* Prototype for original mmap definition */
static unsigned long 
(*original_mmap)(unsigned long addr, 
                 unsigned long len, 
                 unsigned long prot, 
                 unsigned long flags, 
                 unsigned long fd, 
                 unsigned long offset) = NULL;


/* Prototype for original munmap definition */
static int 
(*original_munmap)(unsigned long addr, 
                   size_t        len) = NULL;

/* Prototype for original madvise */
static int
(*original_madvise)(unsigned long addr, 
                    size_t        len, 
                    int           advice) = NULL;

/* Prototype for original mprotect */
static int
(*original_mprotect)(unsigned long start,
                     size_t        len, 
                     unsigned long prot) = NULL;


/* global pid hashtable */
static struct hashtable * pid_map  = NULL;
DEFINE_SPINLOCK(pid_lock);



/* Initialization-type functions */
static int 
initialize_process(struct memory_state * state);

static void 
preallocate_process(struct memory_state * state);

static int 
init_memory_state(struct memory_state * state,
                  u32                   pid);


static struct memory_state * 
find_memory_state(u32 pid);

static u32 
mem_hash_fn(uintptr_t key);

static int
mem_eq_fn(uintptr_t key1, 
          uintptr_t key2);



/* Brk functions */
static int 
hpmmap_brk(unsigned long brk);


/* mmap functions */
static unsigned long 
hpmmap_mmap(unsigned long addr, 
            unsigned long len, 
            unsigned long prot,
            unsigned long flags,
            unsigned long fd, 
            unsigned long offset);

static int 
hpmmap_mprotect(unsigned long addr, 
                size_t        len, 
                unsigned long prot);

static int 
hpmmap_madvise(unsigned long addr,
               size_t        len, 
               int           advice);



/* Utilities for managing mmapings */
static int 
find_allocated_space(u64                 len, 
                     struct mmap_state * state, 
                     struct vaddr_reg ** reg);

static int 
find_allocated_space_fixed(struct allocated_vaddr_reg * alloc,
                           u64                          len, 
                           struct mmap_state          * state, 
                           struct vaddr_reg          ** reg);

static int
create_allocated_space(u64                           len, 
                       u64                           alignment, 
                       struct mmap_state           * state, 
                       struct allocated_vaddr_reg ** reg);

static int 
create_free_space(u64                 start, 
                  u64                 end,
                  struct mmap_state * state,
                  int                 atomic);

static int
remove_vaddr_reg(u64                           start, 
                 u64                           end, 
                 struct mmap_state           * state, 
                 struct allocated_vaddr_reg ** reg,
                 int                           atomic);

static struct vaddr_reg * 
find_vaddr_reg(u64                 start, 
               u64                 end, 
               struct mmap_state * state);

#ifdef DEBUG
static char *
prot_to_str(unsigned long prot);

static char * 
flags_to_str(unsigned long flags);

static void 
dump_mmap_params(unsigned long addr, 
                 unsigned long len,
                 unsigned long prot, 
                 unsigned long flags,
                 unsigned long fd, 
                 unsigned long pgoff);

static void 
dump_vspace(struct memory_state * state);
#endif


/*************************/
/*************************/


/* Initialize the brk for HPMMAP process */
static int 
init_brk_state(struct memory_state * state)
{
    struct brk_state * brk  = state->brk_state;

    brk->brk_base = ALIGN(current->mm->brk, PAGE_SIZE_1GB);
    brk->brk      = brk->brk_base;
    brk->last     = NULL;

    INIT_LIST_HEAD(&(brk->alloc_list));

    return 0;
}

/* Initialize the anonymous mmap for HPMMAP process */
static int
init_mmap_state(struct memory_state * state)
{
    struct mmap_state * mmap = state->mmap_state;

    mmap->mmap_base = MMAP_REGION_START;
    mmap->mmap_max  = MMAP_REGION_END;

    INIT_LIST_HEAD(&(mmap->free_list));
    INIT_LIST_HEAD(&(mmap->alloc_list));
    
    PrintDebug("MMAP Region Base: (%016lx)", (void *)MMAP_REGION_START);
    PrintDebug("MMAP Region Max: (%016lx)", (void *)MMAP_REGION_END);

    /* Add whole vspace region to list */
    create_free_space(mmap->mmap_base, mmap->mmap_max, mmap, 0);

    return 0;
}


static int
initialize_process(struct memory_state * state)
{
    /* Grab the top level pgd setup by Linux */
    state->pgd = (uintptr_t)current->mm->pgd;

    /* Init brk */
    if (init_brk_state(state) == -1) {
        PrintError("Cannot create BRK state\n");
        return -1;
    }

    /* Init mmap */
    if (init_mmap_state(state) == -1) {
        PrintError("Cannot create MMAP state\n");
        return -1;
    }

#ifdef DEBUG
    dump_vspace(state);
#endif

    /* Update ref count */
    atomic_inc(&(state->ref_count));

    /* Set initialized */
    state->initialized = 1;

    return 0;
}

static void 
preallocate_process(struct memory_state * state)
{
    struct allocated_vaddr_reg * allocated_region = NULL;
    struct paddr_reg * physical_region            = NULL;
    struct mmap_state * mmap_state                = state->mmap_state;
    struct brk_state * brk_state                  = state->brk_state;

    if (MMAP_PREALLOCATE) {
        if (!create_allocated_space(MMAP_PREALLOCATE, MMAP_PAGE_SIZE, mmap_state, &allocated_region)) {
            /* Out of virtual memory - not good */
            PrintError("No free virtual address space!\n");
        } else {
            /* Save the page prot */
            allocated_region->pg_prot = HPMMAP_PAGE_PROT;

            if (mem_allocate(state, allocated_region, MMAP_PAGE_SIZE, &physical_region) != 0) {
                PrintError("mem_allocate failed!\n");

                /* Request failed - put vspace back in free list */
                if (!remove_vaddr_reg(allocated_region->start, MMAP_PREALLOCATE, mmap_state, &allocated_region, 0)) {
                    PrintError("Virtual memory management functions are broken!\n");
                }

                list_del(&(allocated_region->node));
                kfree(allocated_region);

                if (!create_free_space(allocated_region->start, MMAP_PREALLOCATE, mmap_state, 0)) {
                    PrintError("Virtual memory management functions are broken!\n");
                }
            } else {
                allocated_region->phys_reg = physical_region;
            }
        }
    }

    if (BRK_PREALLOCATE) {
        allocated_region          = (struct allocated_vaddr_reg *)kmalloc(sizeof(struct allocated_vaddr_reg), GFP_KERNEL);
        allocated_region->start   = brk_state->brk_base;
        allocated_region->end     = allocated_region->start + BRK_PREALLOCATE;

        /* Save the page prot */
        allocated_region->pg_prot = HPMMAP_PAGE_PROT;

        if (mem_allocate(state, allocated_region, BRK_PAGE_SIZE, &physical_region) != 0) {
            PrintError("mem_allocate failed!\n");
        } else {
            /* Update last */
            brk_state->last = allocated_region;

            /* Store it on the list */
            list_add_tail(&(allocated_region->node), &(brk_state->alloc_list));
        }
    }

    state->preallocated = 1;
}


/* Initialize memory state for HPMMAP process */
static int 
init_memory_state(struct memory_state * state,
                  u32                   pid)
{
    /* Initialize spinlock */
    mutex_init(&(state->mutex));

    /* Set ref count */
    atomic_set(&(state->ref_count), 0);

    /* Remember pid */
    state->pid         = pid;

    /* Set initialized */
    state->initialized = 0;

    return 0;
}


static struct memory_state * 
find_memory_state(u32 pid) 
{
    struct memory_state * memory_state = NULL;

    spin_lock(&(pid_lock));
    {
        if (pid_map) {
            memory_state = (struct memory_state *)htable_search(pid_map, (uintptr_t)pid);
        }
    }
    spin_unlock(&(pid_lock));

    return memory_state;
}

static u32 
mem_hash_fn(uintptr_t key)
{
    return util_hash_long(key);
}

static int 
mem_eq_fn(uintptr_t key1, 
          uintptr_t key2)
{
    return (key1 == key2);
}


static int
free_brk(struct memory_state * state, 
         uintptr_t             newbrk) 
{
    struct brk_state * brk_state            = state->brk_state;
    struct allocated_vaddr_reg * alloc_iter = NULL;
    struct allocated_vaddr_reg * prev       = NULL;

    PrintDebug("Freeing brk from (%016lx) to (%016lx)\n", 
           (void *)newbrk, (void *)brk_state->brk);
    
    list_for_each_entry_safe_reverse(alloc_iter, prev, &(brk_state->alloc_list), node) {

        /* Update last */
        brk_state->last = alloc_iter;

        if (alloc_iter->start < newbrk) {
            /* Done free'ing */
            return 0;
        }

        /* Unmap/free memory */
        {
            u64 total_freed = mem_deallocate(state, alloc_iter);

            if (total_freed < 0) {
                return -EFAULT;
            } else if (total_freed == 0) {
                /* Done free'ing */
                return 0;
            }

            /* Free phys reg */
            {
                struct paddr_reg * phys_reg = alloc_iter->phys_reg;
                u64                i        = 0;

                for (i = 0; i < phys_reg->num_pages; i++) {
                    kfree(phys_reg->page_list[i]);
                }

                kfree(phys_reg->page_list);
                kfree(phys_reg);
            }
        }

        /* Free iterator */
        list_del(&(alloc_iter->node));
        kfree(alloc_iter);
    }

    if (list_empty(&(brk_state->alloc_list))) {
        brk_state->last = NULL;
    }
    
    return 0;
}


/* We want to extend the brk from 'oldbrk' by 'brk_size'. 
 *
 * state:  Process' HPMMAP memory state
 * oldbrk: Current brk value. Guaranteed to be BRK_PAGE_SIZE-aligned
 * newbrk: brk value requested. Guaranteed to be BRK_PAGE_SIZE-aligned
 *
 *  Return: 0 on success
 */
static int 
do_hpmmap_brk(struct memory_state * state, 
              uintptr_t             newbrk) 
{
    struct brk_state           * brk_state = state->brk_state;
    struct allocated_vaddr_reg * alloc_reg = brk_state->last;
    struct paddr_reg           * paddr_reg = NULL;
    uintptr_t vaddr_from                   = 0;
    
    vaddr_from = (alloc_reg) ? alloc_reg->end : brk_state->brk_base;

    /* Determine if everything is already mapped */
    if (vaddr_from >= newbrk) {
        return 0;
    }

    /* Need to allocate more memory */
    alloc_reg           = (struct allocated_vaddr_reg *) kmalloc(sizeof(struct allocated_vaddr_reg), GFP_KERNEL);
    alloc_reg->start    = vaddr_from;
    alloc_reg->end      = newbrk;
    alloc_reg->policy   = MEM_NONE;

    /* Save the page prot */
    alloc_reg->pg_prot  = HPMMAP_PAGE_PROT;

    /* Allocate memory */
    {
        int status = mem_allocate(state, alloc_reg, BRK_PAGE_SIZE, &paddr_reg);

        if (status != 0) {
            PrintError("mem_allocate failed!\n");
            kfree(alloc_reg);
            return status;
        }
    }

    /* Save paddr reg */
    alloc_reg->phys_reg = paddr_reg; 

    /* Update last */
    brk_state->last = alloc_reg;

    /* Store it on the list */
    list_add_tail(&(alloc_reg->node), &(brk_state->alloc_list));

    return 0;
}

static int
__hpmmap_brk(struct memory_state * state,
             unsigned long         brk)
{
    struct brk_state * brk_state = state->brk_state;
    unsigned long      oldbrk    = 0;
    unsigned long      newbrk    = 0;
    int                ret       = 0;

    if (!state->initialized) {
        /* Initialize memory regions */
        if (initialize_process(state) != 0) {
            return -1;
        }
    }

    if (!state->preallocated) {
        /* Preallocate memory regions if desired */
        preallocate_process(state);
    }

    PrintDebug("Using HPMMAP for process %d\n", current->pid);
    PrintDebug("Start_brk: %016lx, Current brk: %016lx, Requested brk: %016lx\n", 
           (void *)brk_state->brk_base, (void *)brk_state->brk, (void *)brk);


    if (brk < brk_state->brk_base) {
        return brk_state->brk;
    }

    newbrk = ALIGN(brk, BRK_PAGE_SIZE);
    oldbrk = ALIGN(brk_state->brk, BRK_PAGE_SIZE);

    if (newbrk == oldbrk) {
        brk_state->brk = brk;
        return brk_state->brk;
    }

    if (brk <= brk_state->brk) {
        /* Free pages */
        if (free_brk(state, (uintptr_t)newbrk) == 0) {
            brk_state->brk = brk;
        }

        return brk_state->brk;
    }

    ret = do_hpmmap_brk(state, newbrk);

    switch (ret) {
        case 0:
            /* Success */
            brk_state->brk = brk;
            break;
        case -EFAULT:
            PrintError("brk operation failed: unable to map memory!\n");
            break;
        case -ENOMEM:
            PrintError("brk operation failed: out of memory!\n");
            break;
        default:
            PrintError("brk operation failed: unknown error!\n");
            break;
    }

    return brk_state->brk;
}


static int
hpmmap_brk(unsigned long brk) 
{
    struct memory_state * state  = find_memory_state(current->pid);
    int                   ret    = 0;

    if (!state) {
        /* HPMMAP not enabled for this process, using default brk implementation */
        return original_brk(brk);
    } 

    while (mutex_lock_interruptible(&(state->mutex)));
    {
        ret = __hpmmap_brk(state, brk);
    }
    mutex_unlock(&(state->mutex));

    return ret;
}



static unsigned long 
do_hpmmap_mmap_private(struct memory_state * state,
                       struct file         * file,
                       unsigned long         addr, 
                       size_t                len,
                       unsigned long         prot,
                       unsigned long         fd, 
                       unsigned long         flags, 
                       unsigned long         pgoff)
{
    struct mmap_state          * mmap_state       = state->mmap_state; 
    struct vaddr_reg           * virtual_region   = NULL;
    struct allocated_vaddr_reg * allocated_region = NULL;
    struct paddr_reg           * physical_region  = NULL;

    uintptr_t vaddr     = 0;
    int       ret       = 0;
    u64       page_size = MMAP_PAGE_SIZE;
    u64       alloc_len = ALIGN(len, page_size);

    /* If addr is not NULL, it means userspace is trying a FIXED mapping. If the
     * area is part of an already mmap'd region, we allow it. Otherwise, the
     * user is seemingly grabbing meaningless address and mapping FIXEd there,
     * which is not something we can handle
     */
    PrintDebug("Hpmmap private call at %lu", addr);
    if (addr) {
        virtual_region = find_vaddr_reg(addr, addr + len, mmap_state);

        if (!virtual_region) {
            PrintError("Invalid FIXED memory mapping! We have not mapped this"
               " space yet. Linux might not complain about this, but I don't suspect"
               " that legitimate applications will do this...\n");
            return -ENODEV;
        }

        /* Save the mmap info */
        virtual_region->mmap_flags = flags;
        virtual_region->mmap_pgoff = pgoff;
        virtual_region->mmap_fd    = fd;
        virtual_region->mmap_file  = file;

        /* OK, we've already allocated space for it */
        vaddr = (uintptr_t)addr;

        goto out;
    }

    /* Try to find allocated space that is not yet in use - this will only work if
     * we're using large pages
     */
    PrintDebug("Hpmmap-private find allocated space: %lu", addr);
    if (find_allocated_space(len, mmap_state, &virtual_region)) {
        /* Save the mmap info */
        virtual_region->mmap_flags = flags;
        virtual_region->mmap_pgoff = pgoff;
        virtual_region->mmap_fd    = fd;
        virtual_region->mmap_file  = file;

        /* Found space in an already allocated region */
        vaddr = (uintptr_t)virtual_region->start;

        goto out;
    }

    PrintDebug("Create Allocated Space(%016lx)", (void *)vaddr);
    /* Need to allocate more memory */
    if (!create_allocated_space(alloc_len, page_size, mmap_state, &allocated_region)) {
        /* Out of virtual memory - not good */
        PrintError("No free virtual address space!\n");
        return -EFAULT;
    }

    /* Save the page prot */
    allocated_region->pg_prot = (HPMMAP_PAGE_PROT | prot);
    PrintDebug("Find Allocated Space - Fixed(%016lx)", (void *)vaddr);
    if (!find_allocated_space_fixed(allocated_region, len, mmap_state, &virtual_region)) {
        /* If these functions work, this is impossible */
        PrintError("Virtual memory management functions are broken!\n");
        return -EFAULT;
    }

    /* Save the mmap info */
    virtual_region->mmap_flags = flags;
    virtual_region->mmap_pgoff = pgoff;
    virtual_region->mmap_fd    = fd;
    virtual_region->mmap_file  = file;

    vaddr = (uintptr_t)virtual_region->start;

    /* Allocate memory */
    ret = mem_allocate(state, allocated_region, page_size, &physical_region);
    if (ret != 0) {
        PrintError("mem_allocate failed!\n");
        goto unmap;
    }

    /* Store this in the allocated region */
    allocated_region->phys_reg = physical_region;

out:
    /* Copy file into memory content */
    if (!(flags & MAP_ANONYMOUS)) 
    {
        loff_t pos = pgoff << PAGE_SHIFT;
        PrintDebug("hpmmap_private kernel read - file vaddr: (%016lx), len: (%lu), pos: (%llx), pg_off: (%lx)", (void *)vaddr, len, pos, pgoff);
        kernel_read(file, (void *)vaddr, len, &pos);
    }
    PrintDebug("hpmmap_private - Kernel Read Complete (%016lx)", (void *)vaddr);
    return (unsigned long)vaddr;

 unmap:

    /* Put vspace back in free list */
    if (!remove_vaddr_reg((u64)vaddr, (u64)(vaddr + len), mmap_state, &allocated_region, 0)) {
        PrintError("Virtual memory management functions are broken!\n");
    }

    list_del(&(allocated_region->node));
    kfree(allocated_region);

    if (!create_free_space((u64)vaddr, (u64)(vaddr + alloc_len), mmap_state, 0)) {
        PrintError("Virtual memory management functions are broken!\n");
    }

    return ret;
}

static unsigned long
do_hpmmap_mmap_file(struct memory_state * state, 
                    unsigned long         addr, 
                    size_t                len, 
                    unsigned long         prot, 
                    unsigned long         fd, 
                    unsigned long         flags, 
                    unsigned long         pgoff) 
{
    struct file * file      = NULL;
    unsigned long ret       = 0;

    file = fget(fd);

    if (!file) {
        PrintError("Invalid file descriptor: %lu\n", fd);
        return -EFAULT;
    }
    
    if (!file->f_op || !file->f_op->mmap) {
        return -ENODEV;
    }

#if 0
    if (flags & MAP_SHARED) {
        ret = do_hpmmap_mmap_shared(state, file, addr, len, prot, fd, flags, pgoff);
    } else {
        ret = do_hpmmap_mmap_private(state, file, addr, len, prot, fd, flags, pgoff);
    }
#endif

    ret = do_hpmmap_mmap_private(state, file, addr, len, prot, fd, flags, pgoff);
    PrintDebug("do-hpmmap-mmap-file complete hpmmap-private call: %lu", addr);

    switch (ret) {
        case -ENOMEM:
        case -EFAULT:
        case -ENODEV:
            fput(file);
            return ret;
        default:
            break;
    }

    /* Invoke the file's mmap op on a fake vma */
    {
        struct vm_area_struct fake_vma;
        unsigned long         error;

        fake_vma.vm_start     = ret;
        fake_vma.vm_end       = ret + len;
        fake_vma.vm_pgoff     = pgoff;
        fake_vma.vm_file      = get_file(file);
        fake_vma.vm_mm        = current->mm;

        /* Need to drop the lock temporarily, because the device mmap
         * might invoke get_user_pages leading to deadlock
         */
        mutex_unlock(&(state->mutex));
        {
            error = file->f_op->mmap(file, &fake_vma);
        }
        while (mutex_lock_interruptible(&(state->mutex)));

        if (error) {
            ret = error;
        }
    }

    return ret;
}

/* Map an anonymous region */
static unsigned long
do_hpmmap_mmap_anon(struct memory_state * state, 
                    unsigned long         addr,
                    size_t                len, 
                    unsigned long         prot,
                    unsigned long         flags) 
{
    unsigned long ret = 0;

#if 0
    if (flags & MAP_SHARED) {
        ret = do_hpmmap_mmap_shared(state, file, addr, len, prot, fd, flags, pgoff);
    } else {
        ret = do_hpmmap_mmap_private(state, file, addr, len, prot, fd, flags, pgoff);
    }
#endif
    PrintDebug("hpmmap_anon - call to mmap private %lu\n", addr);
    ret = do_hpmmap_mmap_private(state, NULL, addr, len, prot, -1, flags, 0);
    PrintDebug("do-hpmmap-mmap-anon complete hpmmap-private call: %lu", addr);

    switch (ret) {
        case -ENOMEM:
        case -EFAULT:
        case -ENODEV:
            return ret;
        default:
            break;
    }

    dump_vspace(state);
    PrintDebug("do-hpmmap-mmap-anon memset test: %016lx, len: 10", (void *)ret);
    memset((void *)ret, 0, 10);
    PrintDebug("do-hpmmap-mmap-anon memset ret: %016lx, len: %lu", (void *)ret, len);
    memset((void *)ret, 0, len);
    PrintDebug("do-hpmmap-mmap-anon return: %lu", addr);
    return ret;
}


static unsigned long
__hpmmap_mmap_pgoff(struct memory_state * state,
                    unsigned long         addr, 
                    unsigned long         len,
                    unsigned long         prot, 
                    unsigned long         flags, 
                    unsigned long         fd,
                    unsigned long         pgoff)
{
    unsigned long ret = 0;

#ifdef DEBUG
    PrintDebug("Using HPMMAP for process %d\n", current->pid);
    dump_mmap_params(addr, len, prot, flags, fd, pgoff);
#endif

    if (!len) {
        return -EINVAL;
    }

    len = PAGE_ALIGN(len);
    if (!len) {
        return -ENOMEM;
    }

    switch (flags & MAP_TYPE) {
        case MAP_SHARED:
        case MAP_PRIVATE:
            break;
        default:
            return -EINVAL;
    }

    if (flags & MAP_ANONYMOUS) {
        PrintDebug("Using HPMMAP - mmap anon %d\n", current->pid);
        ret = do_hpmmap_mmap_anon(state, addr, len, prot, flags);
    } else {
        PrintDebug("Using HPMMAP - mmap file %d\n", current->pid);
        ret = do_hpmmap_mmap_file(state, addr, len, prot, fd, flags, pgoff);
    }

    switch (ret) {
        case -EFAULT:
            PrintError("mmap operation failed: unable to map memory!\n");
            break;
        case -ENOMEM:
            PrintError("mmap operation failed: out of memory!\n");
            break;
        case -ENODEV:
            PrintError("mmap operation failed: no such device!\n");
            break;
        case -EINVAL:
            PrintError("mmap operation failed: invalid parameters!\n");
            break;
        default:
            break;
    }

#ifdef DEBUG
    PrintDebug("Dumping state after processing mmap\n");
    dump_vspace(state);
#endif

    return ret;
}


static unsigned long 
hpmmap_mmap(unsigned long addr, 
            unsigned long len,
            unsigned long prot, 
            unsigned long flags, 
            unsigned long fd,
            unsigned long offset)
{
    struct memory_state * state = find_memory_state(current->pid);
    struct mmap_state   * mmap  = NULL;
    unsigned long ret           = 0;
    unsigned long pgoff         = offset >> PAGE_SHIFT;

    if (!state) {
        /* HPMMAP not enabled for this process, using default mmap implementation */
        return original_mmap(addr, len, prot, flags, fd, offset);
    }

    /* We don't currently handle shared mappings, which are a bit more complicated */
    if (flags & MAP_SHARED) {
        return original_mmap(addr, len, prot, flags, fd, offset);
    }

    if (!state->initialized) {
        /* Initialize memory regions */
        if (initialize_process(state) != 0) {
            return -1;
        }
    }

    if (!state->preallocated) {
        /* Preallocate memory regions if desired */
        preallocate_process(state);
    }

    mmap = state->mmap_state;

    /* If a target address is supplied, we need to do a sanity check to make sure it's in
     * the HPMMAP anonymous range
     */
    if ( (addr) && 
         ( (addr < mmap->mmap_base)        ||
           ((addr + len) > mmap->mmap_max)
         )
       ) 
    {

        if (flags & MAP_FIXED) {

            PrintError("Process trying to map a fixed address outside of the HPMMAP"
               " range. We need to let this go and hope Linux can handle it without"
               " anything breaking...\n");


            return original_mmap(addr, len, prot, flags, fd, offset);
        }

        /* Alright, it's not fixed so we should be able to move it - just pretend it was
         * passed in as NULL.
         */
        addr = 0;
    }

    /* Ok, it's ours */
    while (mutex_lock_interruptible(&(state->mutex)));
    {
        ret = __hpmmap_mmap_pgoff(state, addr, len, prot, flags, fd, pgoff);
    }
    mutex_unlock(&(state->mutex));

    return ret;
}

static int
do_hpmmap_munmap_unmap(struct memory_state        * state,
                       struct allocated_vaddr_reg * alloc_reg,
                       int                          atomic)
{
    struct mmap_state * mmap_state      = state->mmap_state;
    struct paddr_reg  * physical_region = alloc_reg->phys_reg;

    u64 total_freed = 0;

    /* Free the memory */
    total_freed = mem_deallocate(state, alloc_reg);

    if (total_freed < 0) {
        /* Should be impossible */
        return -EFAULT;
    } else if (total_freed > 0) {
        u64 i = 0;
        for (i = 0; i < physical_region->num_pages; i++) {
            kfree(physical_region->page_list[i]);
        }

        kfree(physical_region->page_list);
        kfree(physical_region);

        /* Add back to free list */
        if (!create_free_space(alloc_reg->start, alloc_reg->end, mmap_state, atomic)) {
            PrintError("Virtual memory management functions are broken!\n");
            return -EFAULT;
        }

        /* Free memory for allocated region */
        list_del(&(alloc_reg->node));
        kfree(alloc_reg);
    }

    return 0;
}

static int 
do_hpmmap_munmap(struct memory_state * state, 
                 unsigned long         addr, 
                 size_t                len,
                 int                   atomic) 
{
    struct mmap_state          * mmap_state       = state->mmap_state;
    struct vaddr_reg           * virtual_region   = NULL;
    struct allocated_vaddr_reg * allocated_region = NULL;
    struct file                * mmap_file        = NULL;
    unsigned long                mmap_flags       = 0;
    unsigned long                mmap_pgoff       = 0;
    unsigned long                mmap_fd          = 0;
    int                          ret              = 0;

    PrintDebug("munmap(%016lx, %lu)\n", (void *)addr, len);
    len = PAGE_ALIGN_4KB(len);

    if ((virtual_region = find_vaddr_reg(addr, addr + len, mmap_state)) == NULL) {
        PrintError("Could not find a matching virtual address region!\n");
        return -EFAULT;
    }

    /* Grab the mmap info */
    mmap_flags = virtual_region->mmap_flags;
    mmap_pgoff = virtual_region->mmap_pgoff;
    mmap_fd    = virtual_region->mmap_fd;
    mmap_file  = virtual_region->mmap_file;

    /* Remove vaddr region from allocated map */
    if (!remove_vaddr_reg(addr, addr + len, mmap_state, &allocated_region, atomic)) {
        PrintError("Could not find a matching virtual address region!\n");
        return -EFAULT;
    }

    /* Decrement Linux file reference */
    if (!(mmap_flags & MAP_ANONYMOUS)) {
        fput(mmap_file);
    }

    /* Unmap/free memory if there are no more virtual mappings */
    if (list_empty(&(allocated_region->vaddr_list))) {
        /* Only free if num_maps == 0 */
        ret |= do_hpmmap_munmap_unmap(state, allocated_region, atomic);
    }

    return ret;
}


static int
__hpmmap_munmap(struct memory_state * state,
                unsigned long         addr,
                size_t                len)
{
    struct mmap_state * mmap_state = state->mmap_state;
    
    if (!find_vaddr_reg(addr, addr + len, mmap_state)) {
        return -1;
    }

    return do_hpmmap_munmap(state, addr, len, 0);
}

static int 
hpmmap_munmap(unsigned long addr, 
              size_t        len) 
{
    struct memory_state * state = find_memory_state(current->pid);
    int                   ret   = 0;
    
    if (!state) {
        /* HPMMAP not enabled for this process, using default munmap implementation */
        return original_munmap(addr, len);
    }

    if (!state->initialized) {
        /* Initialize memory regions */
        if (initialize_process(state) != 0) {
            return -1;
        }
    }

    while (mutex_lock_interruptible(&(state->mutex)));
    {
        ret = __hpmmap_munmap(state, addr, len);
    }
    mutex_unlock(&(state->mutex));

    /* We couldn't find the memory region - let Linux have it */
    if (ret != 0) {
        return original_munmap(addr, len);
    }

    return ret;
}

static int 
munmap_all(struct memory_state * state)
{
    struct mmap_state          * mmap_state = state->mmap_state;

    struct allocated_vaddr_reg * alloc_iter = NULL;
    struct allocated_vaddr_reg * alloc_next = NULL;

    struct vaddr_reg           * iter       = NULL;
    struct vaddr_reg           * next       = NULL;

    int ret = 0;

    list_for_each_entry_safe(alloc_iter, alloc_next, &(mmap_state->alloc_list), node) {
        /* There could be alloc entries with no mappings if they are persistent regions -
         * free them now
         */
        if (list_empty(&(alloc_iter->vaddr_list))) {
            ret |= do_hpmmap_munmap_unmap(state, alloc_iter, 1);
        }

        list_for_each_entry_safe(iter, next, &(alloc_iter->vaddr_list), node) {
            ret |= do_hpmmap_munmap(state, iter->start, iter->end - iter->start, 1);
        }
    }

    
    /* Free the free list */
    iter = list_first_entry(&(mmap_state->free_list), struct vaddr_reg, node);

    if (!iter) {
        PrintError("munmap_all failed!\n");
    } else {
        list_del(&(iter->node));
        kfree(iter);
    }

    if (!list_empty(&(mmap_state->free_list))) {
        PrintError("munmap_all failed!\n");
    }

    return ret;
}

static int
__hpmmap_mprotect(struct memory_state * state,
                  unsigned long         addr,
                  size_t                len,
                  unsigned long         prot)
{
    struct mmap_state * mmap_state = state->mmap_state;

    if (!find_vaddr_reg(addr, addr + len, mmap_state)) {
        return -1;
    }

    return 0;
}

static int 
hpmmap_mprotect(unsigned long addr, 
                size_t        len, 
                unsigned long prot) 
{
    struct memory_state * state = find_memory_state(current->pid);
    int                   ret   = 0;

    if (!state) {
        return original_mprotect(addr, len, prot);
    }

    if (!state->initialized) {
        /* Initialize memory regions */
        if (initialize_process(state) != 0) {
            return -1;
        }
    }

    while (mutex_lock_interruptible(&(state->mutex)));
    {
        ret = __hpmmap_mprotect(state, addr, len, prot);
    }
    mutex_unlock(&(state->mutex));

    /* We couldn't find the memory region - let Linux have it */
    if (ret != 0) {
        return original_mprotect(addr, len, prot);
    }

    return 0;
}

static int
__hpmmap_madvise(struct memory_state * state,
                 unsigned long         addr,
                 size_t                len,
                 int                   advice)
{
    struct mmap_state * mmap_state = state->mmap_state;
    struct brk_state  * brk_state  = state->brk_state;

    /* Found in an mmap'ed region */
    if (find_vaddr_reg(addr, addr + len, mmap_state)) {
        return 0;
    }

    /* Found in the heap */
    if ( (addr         >= brk_state->brk_base) &&
         ((addr + len) <= brk_state->brk)
       )
    {
        return 0;
    }

    return -1;
}

static int 
hpmmap_madvise(unsigned long addr,
               size_t        len, 
               int           advice) 
{
    struct memory_state * state = find_memory_state(current->pid);
    int                   ret   = 0;

    if (!state) {
        return original_madvise(addr, len, advice);
    }

    if (!state->initialized) {
        /* Initialize memory regions */
        if (initialize_process(state) != 0) {
            return -1;
        }
    }

    while (mutex_lock_interruptible(&(state->mutex)));
    {
        ret = __hpmmap_madvise(state, addr, len, advice);
    }
    mutex_unlock(&(state->mutex));

    /* We couldn't find the memory region - let Linux have it */
    if (ret != 0) {
        return original_madvise(addr, len, advice);
    }

    return 0;
}


int 
register_process(u32 pid) 
{
    struct memory_state * memory_state = NULL;

    memory_state             = kzalloc(sizeof(struct memory_state), GFP_KERNEL);
    memory_state->brk_state  = kzalloc(sizeof(struct brk_state),    GFP_KERNEL);
    memory_state->mmap_state = kzalloc(sizeof(struct mmap_state),   GFP_KERNEL);

    /* Initialize memory state */
    if (init_memory_state(memory_state, pid) == -1) {
        kfree(memory_state->brk_state);
        kfree(memory_state->mmap_state);
        kfree(memory_state);
        return -1;
    }

    /* Store in hashtable */
    spin_lock(&(pid_lock));
    {
        htable_insert(pid_map, pid, (uintptr_t)memory_state);
    }
    spin_unlock(&(pid_lock));

    printk("PID %d registered for HPMMAP management\n", pid);
    return 0;
}

int
register_process_clone(u32 parent_pid, u32 clone_pid)
{
    struct memory_state * parent_memory_state = NULL;

    parent_memory_state = find_memory_state(parent_pid);

    if (!parent_memory_state) {
        return -1;
    }

    /* Update ref count */
    atomic_inc(&(parent_memory_state->ref_count));

    /* Store in hashtable */
    spin_lock(&(pid_lock));
    {
        htable_insert(pid_map, clone_pid, (uintptr_t)parent_memory_state);
    }
    spin_unlock(&(pid_lock));

    return 0;
}

static struct vm_area_struct
fake_vma =
{
    .vm_start = MMAP_REGION_START,
    .vm_end   = MMAP_REGION_END,
    .vm_flags = VM_SPECIAL
};


long 
hpmmap_get_user_pages(u32                      pid, 
                      unsigned long            addr, 
                      unsigned long            nr_pages,
                      struct page           ** pages,
                      struct vm_area_struct ** vmas,
                      int                      flush)
{
    struct memory_state * state = find_memory_state(pid);

    if (!state) {
        return -1;
    }

    if (!state->initialized) {
        return -1;
    }

    {
        long i = 0;

        if (!nr_pages) {
            return 0;
        }

        /* If the caller doesn't want a page list, we're done */
        if (!pages) {
            return nr_pages;
        }

        /* Walk the pts */
        while (i < nr_pages) {
            uintptr_t vaddr          = (uintptr_t)addr + (i * PAGE_SIZE);
            uintptr_t base_page_addr = 0;
            uintptr_t page_off       = 0;
            u64       page_size      = 0;

            base_page_addr = walk_pts(state->pgd, vaddr, &page_off, &page_size);

            if (!base_page_addr) {
                break;
            }

            for (; (page_off < page_size) && (i < nr_pages); page_off += PAGE_SIZE, i++) {
                uintptr_t     page_addr = base_page_addr + page_off;
                struct page * page      = pfn_to_page((unsigned long)(page_addr >> PAGE_SHIFT));

                /* To appease Linux page ref counts */
                get_page(page);

                pages[i] = page;

                /* Fake a vma */
                if (vmas) {
                    vmas[i] = &fake_vma;
                }
            }

        }

        /* Perform a TLB shootdown */
        if (flush && (i > 0)) {
            struct mmu_gather tlb;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
            tlb_gather_mmu(&tlb, current->mm, 0);
#else
            tlb_gather_mmu(&tlb, current->mm, addr, addr + (i * PAGE_SIZE));
#endif
            tlb.need_flush_all = 1;
            tlb_finish_mmu(&tlb, addr, addr + (i * PAGE_SIZE));

            return i;
        }

        return -EFAULT;
    }
}


/* If we can find at least 1 page, we'll handle this request */
int
hpmmap_check_user_pages(u32           pid, 
                        unsigned long addr, 
                        unsigned long nr_pages)
{
    struct memory_state * state = find_memory_state(pid);

    if (!state) {
        return -1;
    }

    if (!state->initialized) {
        return -1;
    }

    {
        uintptr_t base_page_addr = 0;
        uintptr_t page_off       = 0;
        u64       page_size      = 0;

        base_page_addr = walk_pts(state->pgd, addr, &page_off, &page_size);

        return (base_page_addr == 0);
    }
}


static void
do_unmap_process(struct memory_state * state)
{
    struct brk_state    * brk_state  = state->brk_state;
    struct mmap_state   * mmap_state = state->mmap_state;

    /* Set state to deallocating */
    state->deallocating = 1;

    /* Free brk */
    if (free_brk(state, brk_state->brk_base) < 0) {
        PrintError("Could not free process brk!\n");
    } else {
        brk_state->brk = brk_state->brk_base;
    }

    /* Munmap memory regions */
    if (munmap_all(state) != 0) {
        PrintError("Could not free process memory mappings!\n");
    }

#ifdef DEBUG
    PrintDebug("Final VSPACE dump - should ALL be free\n");
    dump_vspace(state);
#endif

    /* Free data structures */
    kfree(brk_state);
    kfree(mmap_state);
}

int 
unmap_process(u32 pid) 
{
    struct memory_state * state = find_memory_state(pid);

    if (!state) {
        return 0;
    }

    /* We always remove the reference */
    spin_lock(&(pid_lock));
    {
        if (!htable_remove(pid_map, pid, 0)) {
            PrintError("Could not remove PID %d from PID map\n", pid);
        }
    }
    spin_unlock(&(pid_lock));

    if (atomic_dec_return(&(state->ref_count)) > 0) {
        /* More threads using this VM - just return */
        return 0;
    }

    /* Alright, all threads have exited, so we unmap memory */
    do_unmap_process(state);
    
    printk("Unmap memory");
    printk("PID %d deregistered\n", state->pid);

    kfree(state);
    state = NULL;

    return 0;
}


/* Intercept brk system call */
static int 
hook_brk_syscall(void) 
{
    void * old_syscall = hook_syscall((void *)hpmmap_brk, __NR_brk);
    
    if (old_syscall == NULL) {
        PrintError("Could not hook brk system call\n");
        return -1;
    }
    
    /* 
     * (int (*)(unsigned long))
     */
    original_brk = old_syscall;

    PrintDebug("Hooked brk system call\n");
    return 0;
}

/* Put original brk back in table */
static int 
unhook_brk_syscall(void) 
{
    if (original_brk) {
        unhook_syscall((void *)original_brk, __NR_brk);
    }

    PrintDebug("Unhooked brk system call\n");
    return 0;
}

/* Intercept mmap system call */
static int
hook_mmap_syscall(void) 
{
    void * old_syscall = hook_syscall((void *)hpmmap_mmap, __NR_mmap);

    if (old_syscall == NULL) {
        PrintError("Could not hook mmap system call\n");
        return -1;
    }

    /*
     * (unsigned long (*)(unsigned long, unsigned long, unsigned long,
     *                    unsigned long, unsigned long, unsigned long)
     */        
    original_mmap = old_syscall;

    PrintDebug("Hooked mmap system call\n");
    return 0;
}

/* Put original mmap back in table */
static int 
unhook_mmap_syscall(void) 
{
    if (original_mmap) {
        unhook_syscall((void *)original_mmap, __NR_mmap);
    }

    PrintDebug("Unhooked mmap system call\n");
    return 0;
}

/* Intercept munmap system call */
static int 
hook_munmap_syscall(void) 
{
    void * old_syscall = hook_syscall((void *)hpmmap_munmap, __NR_munmap);

    if (old_syscall == NULL) {
        PrintError("Could not hook munmap system call\n");
        return -1;
    }

    /* 
     * (int (*)(unsigned long, size_t))
     */
    original_munmap = old_syscall;

    PrintDebug("Hooked munmap system call\n");

    return 0;
}

/* Put original munmap back in table */
static int 
unhook_munmap_syscall(void) 
{
    if (original_munmap) {
        unhook_syscall((void *)original_munmap, __NR_munmap);
    }

    PrintDebug("Unhooked munmap system call\n");
    return 0;
}

/* Intercept mprotect system call */
static int 
hook_mprotect_syscall(void) 
{
    void * old_syscall = hook_syscall((void *)hpmmap_mprotect, __NR_mprotect);

    if (old_syscall == NULL) {
        PrintError("Could not hook mprotect system call\n");
        return -1;
    }

    /* 
     * (int (*)(unsigned long, size_t, unsigned long)) 
     */
    original_mprotect = old_syscall;

    PrintDebug("Hooked mprotect system call\n");
    return 0;
}

/* Put original mprotect back in table */
static int 
unhook_mprotect_syscall(void) 
{
    if (original_mprotect) {
        unhook_syscall((void *)original_mprotect, __NR_mprotect);
    }

    PrintDebug("Unhooked mprotect system call\n");
    return 0;
}

/* Intercept madvise system call */
static int 
hook_madvise_syscall(void)
{
    void * old_syscall = hook_syscall((void *)hpmmap_madvise, __NR_madvise);

    if (old_syscall == NULL) {
        PrintError("Could not hook madvise system call\n");
        return -1;
    }

    /* 
     * int (*)(unsigned long, size_t, int))
     */
    original_madvise = old_syscall;

    PrintDebug("Hooked madvise system call\n");
    return 0;
}

/* Put original madvise back in table */
static int 
unhook_madvise_syscall(void) 
{
    if (original_madvise) {
        unhook_syscall((void *)original_madvise, __NR_madvise);
    }

    PrintDebug("Unhooked madvise system call\n");
    return 0;
}


int
hook_mmap_syscalls(void)
{
    /* Create hashtables */
    pid_map = create_htable(0, mem_hash_fn, mem_eq_fn);

    if (pid_map == NULL) {
        PrintError("Could not allocate pid map\n");
        goto out_pid_map;
    }

    if (hook_brk_syscall() == -1) {
        goto out_brk;
    }

    if (hook_mmap_syscall() == -1) {
        goto out_mmap;
    }

    if (hook_munmap_syscall() == -1) {
        goto out_munmap;
    }

    if (hook_mprotect_syscall() == -1) {
        goto out_mprotect;
    }

    if (hook_madvise_syscall() == -1) {
        goto out_madvise;
    }

    return 0;

out_madvise:
    unhook_mprotect_syscall();

out_mprotect:
    unhook_munmap_syscall();

out_munmap:
    unhook_mmap_syscall();

out_mmap:
    unhook_brk_syscall();

out_brk:
    free_htable(pid_map,  1, 0);
    pid_map = NULL;

out_pid_map:
    return -1;
}


int 
unhook_mmap_syscalls(void)
{
    unhook_brk_syscall();
    unhook_mmap_syscall();
    unhook_munmap_syscall();
    unhook_mprotect_syscall();
    unhook_madvise_syscall();

    /* Delete Hashtables */
    spin_lock(&(pid_lock));
    {
        if (pid_map) {
            free_htable(pid_map,  1, 0);
        }
        pid_map = NULL;
    }
    spin_unlock(&(pid_lock));

    return 0;
}

static struct vaddr_reg * 
alloc_vaddr_reg(int atomic) 
{
    struct vaddr_reg * new_reg = NULL;
    if (atomic) {
        new_reg = (struct vaddr_reg *)kmalloc(sizeof(struct vaddr_reg), GFP_ATOMIC);
    } else {
        new_reg = (struct vaddr_reg *)kmalloc(sizeof(struct vaddr_reg), GFP_KERNEL);
    }

    if (!new_reg) {
        return NULL;
    }

    return new_reg;
}


/* Look for a region of length "len" bytes that is already allocated
 *
 * Returns: 1 if space found, 0 otherwise
 */
static int
find_allocated_space(u64                  len, 
                     struct mmap_state  * state, 
                     struct vaddr_reg  ** reg) 
{
    return find_allocated_space_fixed(NULL, len, state, reg);
}

static int 
find_allocated_space_fixed(struct allocated_vaddr_reg * alloc,
                           u64                          len,
                           struct mmap_state          * state,
                           struct vaddr_reg          ** reg) 
{
    struct allocated_vaddr_reg * alloc_iter = NULL;

    struct vaddr_reg * vaddr_iter = NULL;
    struct vaddr_reg * new_reg    = NULL;

    u64 free_size = 0;
    u64 prev_end  = 0;

    list_for_each_entry(alloc_iter, &(state->alloc_list), node) {
        if ((alloc) && (alloc_iter != alloc)) {
            continue;
        }

        /* Room at beginning? */
        prev_end = alloc_iter->start;

        if (list_empty(&(alloc_iter->vaddr_list))) {
            PrintDebug("Empty vaddr_list in allocated region, start: (%016lx)\n", (void *)prev_end);
        }

        list_for_each_entry(vaddr_iter, &(alloc_iter->vaddr_list), node) {
            
            PrintDebug("find_allocated_space_fixed - new_reg start: (%016lx)\n", (void *)prev_end);
            PrintDebug("find_allocated_space_fixed - vaddr_start: (%016lx)\n", (void *)(vaddr_iter->start));
            PrintDebug("find_allocated_space_fixed - Free space: (%016lx)\n", (void *)(vaddr_iter->start - prev_end));
            PrintDebug("find_allocated_space_fixed - new_reg end: (%016lx)\n", (void *)(prev_end+len));

            free_size = vaddr_iter->start - prev_end;

            if (free_size >= len) {

                new_reg = alloc_vaddr_reg(0);
                if (!new_reg) {
                    return 0;
                }

                new_reg->start      = prev_end;
                new_reg->end        = new_reg->start + len;
                new_reg->alloc_reg  = alloc_iter;
                
                list_add_tail(&(new_reg->node), &(vaddr_iter->node));

                *reg = new_reg;

                return 1;
            }

            prev_end = vaddr_iter->end;
        }

        /* Room at end? */
        PrintDebug("find_allocated_space_fixed - new_reg start: (%016lx)\n", (void *)prev_end);
        PrintDebug("find_allocated_space_fixed - alloc_iter->end: (%016lx)\n", (void *)(alloc_iter->end));
        PrintDebug("find_allocated_space_fixed - Free space: (%016lx)\n", (void *)(alloc_iter->end - prev_end));
        PrintDebug("find_allocated_space_fixed - new_reg end: (%016lx)\n", (void *)(prev_end+len));

        free_size = alloc_iter->end - prev_end;

        if (free_size >= len) {

            new_reg = alloc_vaddr_reg(0);
            if (!new_reg) {
                return 0;
            }

            new_reg->start      = prev_end;
            new_reg->end        = new_reg->start + len;
            new_reg->alloc_reg  = alloc_iter;

            /* Adding immediately before the head is the same as adding to the end */
            list_add_tail(&(new_reg->node), &(alloc_iter->vaddr_list));

            *reg = new_reg;

            return 1;

        }
    }

    PrintDebug("Find allocated space fix - return NULL \n");
    *reg = NULL;

    return 0;
}

/* Create an allocated region of size "len" bytes
 *
 * Returns: 1 if space found, 0 otherwise
 *          If space found, the starting virtual address of the new area is place in "vaddr_start"
 */
static int 
create_allocated_space(u64                           len,
                       u64                           alignment,
                       struct mmap_state           * state, 
                       struct allocated_vaddr_reg ** alloc_reg) 
{
    struct allocated_vaddr_reg * alloc_iter = NULL;
    struct allocated_vaddr_reg * reg        = NULL;

    struct vaddr_reg * free_iter  = NULL;
    struct vaddr_reg * next       = NULL;
    struct vaddr_reg * new_free   = NULL;

    u64 free_size = 0;

    list_for_each_entry_safe(free_iter, next, &(state->free_list), node) {

        /*
         * This is going to be an allocated region, so it needs to be aligned
         */
        PrintDebug("Create-allocated-space Free_iter->start: (%016lx) \n", (void *)free_iter->start);
        PrintDebug("Create-allocated-space Free_iter->end: (%016lx) \n", (void *)free_iter->end);

        free_size = free_iter->end - ALIGN(free_iter->start, alignment);

        if (free_size >= len) {

            reg = kmalloc(sizeof(struct allocated_vaddr_reg), GFP_KERNEL);
            if (!reg) {
                return 0;
            }

            reg->start   = ALIGN(free_iter->start, alignment);
            reg->end     = reg->start + len;
            reg->policy  = MEM_NONE;

            PrintDebug("Create vaddr_list node head for alloc\n");
            INIT_LIST_HEAD(&(reg->vaddr_list));

            /* 
             * The region is big enough - now fix up any holes that we left 
             */
            if ((reg->start != free_iter->start) && 
                (reg->end   != free_iter->end))
            {

                /* 
                 * We took a piece out of the middle, which means we need to adjust 
                 * and create a new region
                 */

                new_free = alloc_vaddr_reg(0);
                if (!new_free) {
                    return 0;
                }

                new_free->start  = reg->end;
                new_free->end    = free_iter->end;

                list_add(&(new_free->node), &(free_iter->node));

                free_iter->end   = reg->start;

            } else if (reg->start != free_iter->start) {

                /* Only the front needs adjusted */
                free_iter->end   = reg->start;  

            } else if (reg->end != free_iter->end) {

                /* Only back needs adjusted */
                free_iter->start = reg->end;

            } else {

                /* Exact fit - delete iterator entirely */
                list_del(&(free_iter->node));
                kfree(free_iter);

            }

            /*
             * Alright, so now we need to put this on the alloc list
             * Note that we don't want to merge allocated entries
             */
            if (list_empty(&(state->alloc_list))) {

                list_add(&(reg->node), &(state->alloc_list));

            } else {

                list_for_each_entry(alloc_iter, &(state->alloc_list), node) {

                    if (reg->end <= alloc_iter->start) {

                        /* Match */
                        list_add_tail(&(reg->node), &(alloc_iter->node));

                        /* *vaddr_start = (uintptr_t)reg->start; */
                        *alloc_reg = reg;

                        return 1;
                    }
                }

                /* Must fit at the end */
                list_add_tail(&(reg->node), &(state->alloc_list));
            }
         
            *alloc_reg = reg;

            return 1;
        }
    }

    *alloc_reg = NULL;

    return 0;
}

/* Create a free region from "start" to "end" in the free list
 * Merges with existing region(s) if possible
 *
 * Returns: 1 if region created, 0 otherwise
 */
static int 
create_free_space(u64                 start, 
                  u64                 end, 
                  struct mmap_state * state,
                  int                 atomic) 
{
    struct vaddr_reg * iter       = NULL;
    struct vaddr_reg * prev_iter  = NULL;
    struct vaddr_reg * next       = NULL;
    struct vaddr_reg * new_reg    = NULL;


    /* Empty list, so we just insert and go */
    if (list_empty(&(state->free_list))) {

        new_reg = alloc_vaddr_reg(atomic);
        if (!new_reg) {
            return 0;
        }

        new_reg->start  = start;
        new_reg->end    = end;

        list_add(&(new_reg->node), &(state->free_list));

        return 1;
    }

    prev_iter = NULL;

    /* 
     * We have to find the fight location to insert or merge into 
     */
    list_for_each_entry_safe(iter, next, &(state->free_list), node) {

        /* Could be before any entries */
        if (end < iter->start) {

            /* Check for invalid overlap */
            if ((prev_iter) && (start < prev_iter->end)) {
                return 0;
            }

            /* OK, it's a match */
            if ((prev_iter) && (prev_iter->end == start)) {

                /* Merge */
                prev_iter->end = end;

            } else {

                /* No merge possible */
                new_reg = alloc_vaddr_reg(atomic);
                if (!new_reg) {
                    return 0;
                }

                new_reg->start  = start;
                new_reg->end    = end;
  
                list_add_tail(&(new_reg->node), &(iter->node));
            }

            return 1;

        } else if (end == iter->start) {
           
            /* Check for invalid overlap */
            if ((prev_iter) && (start < prev_iter->end)) {
                return 0;
            }

            /* OK, it's a match, and we can merge at the end */
            iter->start = start;

            if ((prev_iter) && (prev_iter->end == start)) {

                /* Perfect match, we merge with this and previous- free previous */
                iter->start = prev_iter->start;
                list_del(&(prev_iter->node));
                kfree(prev_iter);

            }

            /*
             * No merge at the front, but we already merged the back so it's all good
            */

            return 1;
        }

        prev_iter = iter;
    }

    /* Must be after the last region */

    /* Invalid overlap */
    if (start < prev_iter->end) {
        return 0;
    }

    /* Ok, it's at the end */
    if (start == prev_iter->end) {
 
        /* Merge */
        prev_iter->end = end;
    } else {

        new_reg = alloc_vaddr_reg(atomic);
        if (!new_reg) {
            return 0;
        }

        new_reg->start  = start;
        new_reg->end    = end;
        list_add(&(new_reg->node), &(prev_iter->node));
    }

    return 1;
}

/* Remove a virtual address region from "start" to "end"
 *
 * Returns: 1 if the region was found in an allocated list, 0 otherwise
 *          If region found, associated allocated region is stored in "region"
 */
static int
remove_vaddr_reg(u64                           start, 
                 u64                           end, 
                 struct mmap_state           * state, 
                 struct allocated_vaddr_reg ** region,
                 int                           atomic) 
{
    struct allocated_vaddr_reg * alloc_iter = NULL;

    struct vaddr_reg * vaddr_iter = NULL;
    struct vaddr_reg * next       = NULL;
    struct vaddr_reg * new_reg    = NULL;

    list_for_each_entry(alloc_iter, &(state->alloc_list), node) {

        list_for_each_entry_safe(vaddr_iter, next, &(alloc_iter->vaddr_list), node) {

            if (vaddr_iter->start <= start && vaddr_iter->end >= end) {

                /* Ok, found it */
                if ((vaddr_iter->start == start) && 
                    (vaddr_iter->end   == end)) {

                    /* Exact */
                    list_del(&(vaddr_iter->node));
                    kfree(vaddr_iter);

                } else if ((vaddr_iter->start < start) && 
                           (vaddr_iter->end   > end)) {

                    /* Actually need to create a new region at the front */
                    new_reg = alloc_vaddr_reg(atomic);
                    if (!new_reg) {
                        return 0;
                    }

                    new_reg->start    = vaddr_iter->start;
                    new_reg->end      = start;

                    list_add_tail(&(new_reg->node), &(vaddr_iter->node));

                    /* And adjust the back */
                    vaddr_iter->start = end;

                } else if (vaddr_iter->start < start) {

                    /* Adjust front */
                    vaddr_iter->end = start;
                } else {

                    /* Adjust back */
                    vaddr_iter->start = end;
                }

                *region = alloc_iter;

                return 1;
            }
        }
    }

    return 0;
}

/* Determine whether or not we have mapped the range [start, end]
 *
 * Returns: Pointer to the region if we have, NULL otherwise
 */
static struct vaddr_reg * 
find_vaddr_reg(u64                 start, 
               u64                 end, 
               struct mmap_state * state) 
{
    struct allocated_vaddr_reg * alloc_iter = NULL;
    struct vaddr_reg * vaddr_iter           = NULL;

    list_for_each_entry(alloc_iter, &(state->alloc_list), node) {

        list_for_each_entry(vaddr_iter, &(alloc_iter->vaddr_list), node) {

            if ((vaddr_iter->start <= start) && 
                (vaddr_iter->end   >= end)) {
                return vaddr_iter;
            }

        }
    }
    
    return NULL;
}

#ifdef DEBUG
static char * 
prot_to_str(unsigned long prot) 
{

    unsigned long  prot_arr[] = {  PROT_EXEC,   PROT_READ,   PROT_WRITE,   PROT_NONE,  0 };
    char         * name_arr[] = { "PROT_EXEC", "PROT_READ", "PROT_WRITE", "PROT_NONE", NULL };
    char         * str        = kzalloc(sizeof(char) * 64, GFP_KERNEL);

    int i         = 0;
    int first_val = 1;

    if (!str) {
        return NULL;
    }

    for (i = 0; name_arr[i] != NULL; i++) {
        if (prot & prot_arr[i]) {

            if (!first_val) {
                strcat(str, " | ");
            }

            strcat(str, name_arr[i]);
            first_val = 0;
        }
    }

    return str;
}

static char * 
flags_to_str(unsigned long flags) 
{
    unsigned long  flag_arr[] = { MAP_SHARED,    MAP_PRIVATE,    MAP_32BIT,  MAP_ANONYMOUS,
                  MAP_DENYWRITE, MAP_EXECUTABLE, MAP_FILE,   MAP_FIXED, 
                  MAP_GROWSDOWN, MAP_HUGETLB,    MAP_LOCKED, MAP_NONBLOCK, 
                  MAP_NORESERVE, MAP_POPULATE,   MAP_STACK,  MAP_UNINITIALIZED, 
                  0 };
    char         * name_arr[] = { "MAP_SHARED",       "MAP_PRIVATE",       "MAP_32BIT **",  "MAP_ANONYMOUS",
                  "MAP_DENYWRITE **", "MAP_EXECUTABLE **", "MAP_FILE **",   "MAP_FIXED",
                  "MAP_GROWSDOWN **", "MAP_HUGETLB **",    "MAP_LOCKED **", "MAP_NONBLOCK **", 
                  "MAP_NORESERVE **", "MAP_POPULATE **",   "MAP_STACK **",  "MAP_UNINITIALIZED **",
                  NULL };
    char         * str       = kzalloc(sizeof(char) * 256, GFP_KERNEL);

    int i         = 0;
    int first_val = 1;

    if (!str) {
        return NULL;
    }

    for (i = 0; name_arr[i] != NULL; i++) {
        if (flags & flag_arr[i]) {

            if (!first_val) {
                strcat(str, " | ");
            }

            strcat(str, name_arr[i]);
            first_val = 0;
        }
    }


    return str;
}

static void 
dump_mmap_params(unsigned long addr, 
                 unsigned long len,
                 unsigned long prot, 
                 unsigned long flags, 
                 unsigned long fd,
                 unsigned long pgoff) 
{

    char * prot_str = prot_to_str(prot);
    char * flag_str = flags_to_str(flags);

    PrintDebug("mmap params:\n");
    PrintDebug("    addr:  %016lx\n",       (void *)addr);
    PrintDebug("    len:   %lu\n",      len);
    PrintDebug("    prot:  %lu (%s)\n", prot, prot_str);
    PrintDebug("    flags: %lu (%s)\n", flags, flag_str);
    PrintDebug("    fd:    %lu\n",      fd);
    PrintDebug("    pgoff: %lu\n",      pgoff);

    if (prot_str) {
        kfree(prot_str);
    }

    if (flag_str) {
        kfree(flag_str);
    }
}


static void 
dump_vspace(struct memory_state * mem_state) 
{
    struct vaddr_reg           * vaddr_iter = NULL;
    struct allocated_vaddr_reg * alloc_iter = NULL;
    struct brk_state           * brk_state  = mem_state->brk_state;
    struct mmap_state          * mmap_state = mem_state->mmap_state;

    PrintDebug("brk state: \n");
    PrintDebug("    brk_base:  %016lx\n", (void *)brk_state->brk_base);
    PrintDebug("    brk:       %016lx\n", (void *)brk_state->brk);

    if (!list_empty(&(brk_state->alloc_list))) {

        PrintDebug("Alloc list: \n");

        list_for_each_entry(alloc_iter, &(brk_state->alloc_list), node) {
            PrintDebug("\tStart:     %016lx\n", (void *)alloc_iter->start);
            PrintDebug("\tEnd:       %016lx\n", (void *)alloc_iter->end);
            PrintDebug("\tPolicy:    %s\n",  mem_policy_to_str(alloc_iter->policy));
        }
    }

    PrintDebug("\n");
    PrintDebug("mmap state: \n");

    if (!list_empty(&(mmap_state->free_list))) {

        PrintDebug("Free list: \n");

        list_for_each_entry(vaddr_iter, &(mmap_state->free_list), node) {
            PrintDebug("\tStart:     %016lx\n", (void *)vaddr_iter->start);
            PrintDebug("\tEnd:       %016lx\n", (void *)vaddr_iter->end);
            PrintDebug("\n");
        }
    }

    if (!list_empty(&(mmap_state->alloc_list))) {

        PrintDebug("Alloc list: \n");

        list_for_each_entry(alloc_iter, &(mmap_state->alloc_list), node) {
            PrintDebug("\tStart:     %016lx\n", (void *)alloc_iter->start);
            PrintDebug("\tEnd:       %016lx\n", (void *)alloc_iter->end);
            PrintDebug("\tPolicy:    %s\n",  mem_policy_to_str(alloc_iter->policy));
            PrintDebug("\n");

            PrintDebug("\tMappings: \n");

            list_for_each_entry(vaddr_iter, &(alloc_iter->vaddr_list), node) {
                PrintDebug("\t\tStart:     %016lx\n", (void *)vaddr_iter->start);
                PrintDebug("\t\tEnd:       %016lx\n", (void *)vaddr_iter->end);
                PrintDebug("\n");
            }
        }
    }
}
#endif




/* Preliminary attempt at MAP_SHARED support is below */
#if 0
static int
create_file_mapping(struct memory_state * state,
                    struct file         * file,
                    unsigned long         page_size,
                    unsigned long         prot,
                    unsigned long         fd,
                    unsigned long         flags,
                    struct paddr_reg    * file_mapping,
                    struct paddr_reg   ** phys_reg)
{
    struct mmap_state          * mmap_state        = state->mmap_state; 
    struct vaddr_reg           * file_virt_region  = NULL;
    struct allocated_vaddr_reg * file_alloc_region = NULL;
    struct paddr_reg           * file_phys_region  = NULL;

    uintptr_t vaddr       = 0;
    int       ret         = 0;
    u64       alloc_len   = 0;
    u64       file_len    = 0;

    /* Read the file size via vfs */
    {
        struct kstat stat;

        vfs_fstat(fd, &stat);
        file_len = stat.size;
    }

    /* Round to the nearest page size */
    alloc_len = ALIGN(file_len, page_size);

    if (!create_allocated_space(alloc_len, page_size, mmap_state, &file_alloc_region)) {
        /* Out of virtual memory - not good */
        PrintError("No free virtual address space!\n");
        return -ENOMEM;
    }

    /* Save the page prot */
    file_alloc_region->pg_prot = HPMMAP_PAGE_PROT;

    if (!find_allocated_space_fixed(file_alloc_region, file_len, mmap_state, &file_virt_region)) {
        /* If these functions work, this is impossible */
        PrintError("Virtual memory management functions are broken!\n");
        return -EFAULT;
    }

    /* Save the mmap info */
    file_virt_region->mmap_flags = flags;
    file_virt_region->mmap_pgoff = 0;
    file_virt_region->mmap_fd    = fd;
    file_virt_region->mmap_file  = file;

    vaddr = (uintptr_t)file_virt_region->start;

    /* If memory has already been allocated, map it here. Otherwise, allocate
     * memory and copy in the file contents
     */
    if (file_mapping != NULL) {
        ret = mem_map_region(state, file_alloc_region, file_mapping);
        if (ret != 0) {
            PrintError("mem_map_region failed!\n");
            goto unmap;
        }
    } else {
        /* Allocate memory, map in the file contents */
        ret = mem_allocate(state, file_alloc_region, page_size, &file_phys_region);
        if (ret != 0) {
            PrintError("mem_allocate failed!\n");
            goto unmap;
        }

        /* Copy the file into this region */
        {
           loff_t pos = 0;
           kernel_read(file, (void *)vaddr, file_len, &pos);
        }

        /* Save phys reg pointer */
        *phys_reg = file_phys_region;
    }

    return 0;

unmap:
    /* Put vspace back in free list */
    if (!remove_vaddr_reg((u64)vaddr, (u64)(vaddr + alloc_len), mmap_state, &file_alloc_region)) {
        PrintError("Virtual memory management functions are broken!\n");
    }

    list_del(&(file_alloc_region->node));
    kfree(file_alloc_region);

    if (!create_free_space((u64)vaddr, (u64)(vaddr + alloc_len), mmap_state)) {
        PrintError("Virtual memory management functions are broken!\n");
    }

    return ret;
}

/* Get the physical address region backing file 'file'.
 *
 * This will update page reference counts and ensure that the whole file is
 * mapped into our address space.
 *
 * Returns: 0 if succeessful, an error code otherwise
 */
static int
get_file_phys_region(struct memory_state * state,
                     struct file         * file,
                     unsigned long         page_size,
                     unsigned long         prot,
                     unsigned long         fd,
                     struct paddr_reg   ** phys_region)
{
    struct paddr_reg * file_phys_region = NULL;
    int                ret              = 0;

    /* Determine if we've mapped the file yet */
    ret = get_file_info(state, file, &file_phys_region);

    if (ret > 0) {
        /* We've mapped it - this is simple */
        *phys_region = file_phys_region;
        return 0;
    }

    /* So, we haven't mapped it yet - see if it's mapped by any other process */
    lock_file_map();

    /* Determine if any other process has mapped this file */
    ret = get_global_file_info(file, &file_phys_region);

    if (ret <= 0) {
        /* It's not mapped anywhere */
        ret = create_file_mapping(
                state, 
                file, 
                page_size,
                prot,
                fd,
                HPMMAP_PAGE_PROT,
                NULL,
                &file_phys_region);

        if (ret != 0) {
            PrintError("Cannot create file mapping\n");
            goto err_file_global;
        }

        /* Update the file info map */
        ret = add_global_file_info(file, file_phys_region);

        if (ret != 0) {
            PrintError("Cannot update global file map\n");
            goto err_file_global;
        }

        /* Unlock the map */
        unlock_file_map();

    } else {
        /* The file is mapped in someone's address space. We create a
         * new physical region, grabbing the pfns from the existing
         * mapping
         */
        ret = create_file_mapping(
                state, 
                file, 
                page_size,
                prot,
                fd,
                HPMMAP_PAGE_PROT,
                file_phys_region,
                NULL);

        if (ret != 0) {
            PrintError("Cannot create file mapping\n");
            goto err_file_global_put;
        }

        /* Unlock the map */
        unlock_file_map();
    }

    /* Update local file map */
    ret = add_file_info(state, file, file_phys_region);

    if (ret != 0) {
        PrintError("Cannot update process file map\n");
        goto err_file_local;
    }

    /* Success */
    *phys_region = file_phys_region;
    return 0;

err_file_local:
    lock_file_map();

err_file_global_put:
    put_global_file_info(file, &file_phys_region);

err_file_global:
    unlock_file_map();

    return ret;
}

/* Map the first 'file_len' bytes (starting at page offset 'pgoff') of the phys
 * region 'file_mapping' into 'file_alloc_region'
 * 
 * Returns: 0 if successful, an error code otherwise */
static int
map_file_phys_region(struct memory_state        * state,
                     unsigned long                page_size,
                     unsigned long                file_len,
                     unsigned long                pgoff,
                     struct allocated_vaddr_reg * file_alloc_region,
                     struct paddr_reg           * file_mapping)
{
    struct paddr_reg * file_phys_region = NULL;
    u64                num_pages        = file_len / page_size;

    /* Make sure we don't overflow the page list */
    if (num_pages > (pgoff + file_mapping->num_pages)) {
        return -EINVAL;
    }

    file_phys_region = kmalloc(sizeof(struct paddr_reg), GFP_KERNEL);
    if (!file_phys_region) {
        PrintError("Out of memory!\n");
        return -ENOMEM;
    }

    file_phys_region->num_pages = num_pages; 
    file_phys_region->page_list = kmalloc(sizeof(struct mapped_page *) * file_mapping->num_pages, GFP_KERNEL);

    if (!file_phys_region->page_list) {
        kfree(file_phys_region);
        PrintError("Out of memory!\n");
        return -ENOMEM;
    }

    /* Copy/map the page list */
    {
        u64 i = 0;

        for (i = 0; i < num_pages; i++) {
            /* The  map the file memory up to the file length */
            /* The last 'num_pages - pgoff' are zeroed */
            file_phys_region->page_list[i] = kmalloc(sizeof(struct mapped_page), GFP_KERNEL);
            
            if (!file_phys_region->page_list[i]) {
                PrintError("Out of memory!\n");

                while (i-- > 0) {
                    kfree(file_phys_region->page_list[i]);
                }

                kfree(file_phys_region->page_list);
                kfree(file_phys_region);

                return -ENOMEM;
            }

            /* Grab the mapped page */
            {
                u64 file_pg_idx = i + pgoff;

                file_phys_region->page_list[i]->paddr = file_phys_region->page_list[file_pg_idx]->paddr;
                file_phys_region->page_list[i]->size  = page_size;
            }
        }
    }

    /* Map the allocated region to the pfn range */
    {
        int ret = mem_map_region(state, file_alloc_region, file_phys_region);

        if (ret != 0) {
            PrintError("mem_map_region failed!\n"); 

            /* Free up */
            {
                u64 i = 0;
                for (i = 0; i < num_pages; i++) {
                    kfree(file_phys_region->page_list[i]);
                }
            }

            kfree(file_phys_region->page_list);
            kfree(file_phys_region);

            return ret;
        }
    }

    /* Save the phys region pointer */
    file_alloc_region->phys_reg = file_phys_region;

    return 0;
}



/* Map a shared file. The approach to shared mappings is more complicated than
 * private mappings.
 *
 * (1) If the file has already been mapped by this process, go to (2).
 * Otherwise, map the entire file contents into our address space, either
 * reading the file contents from vfs or through a pfn list setup by another
 * process if the file has been mapped shared elsewhere.
 *
 * (2) Allocate ALIGN('len', 'page_size') bytes of address space.
 *
 * (3) If the file size is >= 'len' bytes, copy the first 'len' bytes of the
 * file contents into the allocated region from (2). Return.
 *
 * (4) If the file size is < 'len' bytes, split the allocated region from (2)
 * into 2 contiguous regions, the first the size of the file, and the second
 * 'len' - the size of the file. Copy the file contents into the first region,
 * leave the remaining bytes uninitialized
 *
 * Returns: The address of the new mapping, if successful. An error code
 * otherwise.
 */
static unsigned long
do_hpmmap_mmap_shared(struct memory_state * state,
                      struct file         * file,
                      unsigned long         addr,
                      size_t                len,
                      unsigned long         prot,
                      unsigned long         fd,
                      unsigned long         flags,
                      unsigned long         pgoff)
{
    struct mmap_state          * mmap_state        = state->mmap_state; 
    struct vaddr_reg           * file_virt_region  = NULL;

    struct allocated_vaddr_reg * file_alloc_region = NULL;
    struct paddr_reg           * file_phys_region  = NULL;

    struct allocated_vaddr_reg * anon_alloc_region = NULL;
    struct paddr_reg           * anon_phys_region  = NULL;
 
    uintptr_t vaddr       = 0;
    uintptr_t split_vaddr = 0;
    int       ret         = 0;
    u64       alloc_len   = 0;
    u64       file_len    = 0;
    u64       page_size   = MMAP_PAGE_SIZE_SHARED;

    /* If addr is not NULL, it was specified as MAP_FIXED */
    if (addr) {
        PrintError("We do not support SHARED and FIXED memory mappings at this point!\n");
        return -ENODEV;
    }

    /* We have no way of doing shared anonymous mappings! */
    if (flags & MAP_ANONYMOUS) {
        PrintError("We do not support anonymous shared mappings!\n");
        return -ENODEV;
    }

    /* Read the file size via vfs */
    {
        struct kstat stat;
        vfs_fstat(fd, &stat);
        file_len = ALIGN(stat.size, page_size);
    }

    /* Get file physical backing region */
    ret = get_file_phys_region(
            state, 
            file, 
            page_size,
            prot,
            fd,
            &file_phys_region);

    if (ret != 0) {
        PrintError("Cannot get file physical address region\n");
        return -EFAULT;
    }

    /* Map the file contents into our address space */
    alloc_len = ALIGN(len, page_size);

    /* Create an allocated region that we're going to split */
    if (!create_allocated_space(alloc_len, page_size, mmap_state, &file_alloc_region)) {
        /* Out of virtual memory - not good */
        PrintError("No free virtual address space!\n");
        ret = -ENOMEM;
        goto put;
    }

    /* Save the page prot */
    file_alloc_region->pg_prot = HPMMAP_PAGE_PROT;

    if (!find_allocated_space_fixed(file_alloc_region, alloc_len, mmap_state, &file_virt_region)) {
        /* If these functions work, this is impossible */
        PrintError("Virtual memory management functions are broken!\n");
        ret = -EFAULT;
        goto put;
    }

    /* Save the mmap info */
    file_virt_region->mmap_flags = flags;
    file_virt_region->mmap_pgoff = 0;
    file_virt_region->mmap_fd    = fd;
    file_virt_region->mmap_file  = file;

    vaddr = (uintptr_t)file_virt_region->start;

    /* Truncate the file len to alloc len */
    if (file_len > alloc_len) {
        file_len = alloc_len;
    }

    /* Map the file contents in */
    ret = map_file_phys_region(
            state,
            page_size,
            file_len,
            pgoff,
            file_alloc_region,
            file_phys_region);

    if (ret != 0) {
        PrintError("Cannot map file contents\n");
        goto unmap;
    }

    /* Determine if we need to buffer with an anonymous region */
    if (alloc_len > file_len) {

        /* So, we need to split the file alloc region into two separate regions */
        if (split_allocated_space(
                file_alloc_region,
                file_len,
                page_size,
                state->mmap_state,
                &anon_alloc_region) == 0)
        {
            PrintError("Cannot split allocated region [%p, %p) at offset %lu\n",
                (void *)file_alloc_region->start,
                (void *)file_alloc_region->end,
                (unsigned long)file_len);
            ret = -EFAULT;
            goto unmap;
        }

        /* Copy the page prot */
        anon_alloc_region->pg_prot = HPMMAP_PAGE_PROT;

        /* Save the split virtual address */
        split_vaddr = vaddr + anon_alloc_region->start;

        /* Allocate memory */
        ret = mem_allocate(state, anon_alloc_region, page_size, &anon_phys_region);
        if (ret != 0) {
            PrintError("mem_allocate failed!\n");
            goto split_unmap;
        }

        /* Store this in the allocated region */
        anon_alloc_region->phys_reg = anon_phys_region;
    }

    return (unsigned long)vaddr;

split_unmap:
    /* Remove the second half of the split */
    if (!remove_vaddr_reg((u64)split_vaddr, (u64)(vaddr + len), mmap_state, &anon_alloc_region)) {
        PrintError("Virtual memory management functions are broken!\n");
    }

    list_del(&(anon_alloc_region->node));
    kfree(anon_alloc_region);

    if (!create_free_space((u64)split_vaddr, (u64)(vaddr + alloc_len), mmap_state)) {
        PrintError("Virtual memory management functions are broken!\n");
    }

    /* Set the lengths to remove the first half of the split */
    len       = file_len;
    alloc_len = ALIGN(len, page_size);

unmap:

    /* Put vspace back in free list */
    if (!remove_vaddr_reg((u64)vaddr, (u64)(vaddr + len), mmap_state, &file_alloc_region)) {
        PrintError("Virtual memory management functions are broken!\n");
    }

    list_del(&(file_alloc_region->node));
    kfree(file_alloc_region);

    if (!create_free_space((u64)vaddr, (u64)(vaddr + alloc_len), mmap_state)) {
        PrintError("Virtual memory management functions are broken!\n");
    }

put:

    /* Decrement file map count */
    if (put_file_info(state, file, &file_phys_region) == 0) {
        lock_file_map();
        put_global_file_info(file, &file_phys_region);
        unlock_file_map();
    }

    return ret;
}

/* Split the allocated region "alloc" at offset "split" into 2 regions
 *
 * Returns: 1 if split achieved, 0 otherwise
 *          If split achieved, the new region starting at "split" is placed
 *          in "*split_reg"
 */
static int
split_allocated_space(struct allocated_vaddr_reg  * alloc_reg,
                      u64                           split,
                      int                           page_size,
                      struct mmap_state           * state,
                      struct allocated_vaddr_reg ** split_reg)
{
    struct allocated_vaddr_reg * new_reg = NULL;
    u64                          len     = 0;
    
    len   = alloc_reg->end - alloc_reg->start;
    split = ALIGN(split, page_size);

    if (split >= len) {
        return 0;
    }

    new_reg = kmalloc(sizeof(struct allocated_vaddr_reg), GFP_KERNEL);
    if (!new_reg) {
        return 0;
    }

    /* Set new reg */
    new_reg->start = split;
    new_reg->end   = alloc_reg->end;
    INIT_LIST_HEAD(&(new_reg->vaddr_list));

    /* Adjust existing reg */
    alloc_reg->end = alloc_reg->start + split; 

    /* Add new reg to the list */
    list_add_tail(&(new_reg->node), &(alloc_reg->node));

    /* Move mappings to the new region */
    {
        struct vaddr_reg * iter = NULL;
        struct vaddr_reg * next = NULL;

        list_for_each_entry_safe(iter, next, &(alloc_reg->vaddr_list), node) {
            if (iter->start >= split) {
                list_del(&(iter->node));
                list_add_tail(&(iter->node), &(new_reg->vaddr_list));
            }
        }
    }

    return 1;
}
#endif
