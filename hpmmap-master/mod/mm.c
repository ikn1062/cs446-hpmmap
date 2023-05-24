#include <linux/slab.h>

#include "hpmmap.h"
#include "mm.h"
#include "mapper.h"
#include "pgtables.h"

static uintptr_t 
node_allocate(struct memory_state * state, 
              u64                   num_pages);

/*
 * Function: Allocate memory to back the region specified in alloc_reg
 *
 * state:       Process' HPMMAP state
 * alloc_reg:   Virtual address region to be backed
 * page_size:   Physical page size
 * phys_reg:    (out) Physical address region allocated
 *
 * Returns:     0 on success, < 0 otherwise
 */
int 
mem_allocate(struct memory_state        * state, 
             struct allocated_vaddr_reg * alloc_reg, 
             u64                          page_size, 
             struct paddr_reg          ** reg) 
{
    PrintDebug("mem_allocate function call\n");
    struct paddr_reg * phys_reg = NULL;

    uintptr_t vaddr = 0;
    uintptr_t paddr = 0;

    u64 num_pages   = 0;
    u64 alloc_pages = 0;
    u64 start       = 0;
    u64 len         = 0;
    u64 i           = 0;
    int ret         = 0;

    PrintDebug("mem_allocate start %p end %p", (void *)alloc_reg->start, (void *)alloc_reg->end);
    start       = alloc_reg->start;
    start       = ALIGN(start, page_size);
    PrintDebug("mem_allocate alligned start %p", (void *)start);

    len         = alloc_reg->end - start;
    PrintDebug("mem_allocate unalligned len: %llu", len);
    len         = ALIGN(len, page_size);
    PrintDebug("mem_allocate alligned len: %llu", len);

    num_pages   = len       / page_size;
    PrintDebug("mem_allocate num_pages %llu page size %llu", num_pages, page_size);
    alloc_pages = page_size / PAGE_SIZE_4KB;

    vaddr       = (uintptr_t)start;

    PrintDebug("mem_allocate vaddr start (%p)\n", (void *)vaddr);
    PrintDebug("mem_allocate start (%llu) len (%llu) num_pages (%llu) alloc_pages (%llu)\n", start, len, num_pages, alloc_pages);
    if (reg) {
        PrintDebug("mem_allocate allocate phys_reg\n");
        phys_reg            = (struct paddr_reg    *)kmalloc(sizeof(struct paddr_reg),                 GFP_KERNEL);
        PrintDebug("mem_allocate allocate phys_reg - page list\n");
        phys_reg->page_list = (struct mapped_page **)kmalloc(sizeof(struct mapped_page *) * num_pages, GFP_KERNEL);
        PrintDebug("mem_allocate allocate set num pages - page list\n");
        phys_reg->num_pages = num_pages;

        PrintDebug("mem_allocate allocate phys_reg for num pages\n");
        for (i = 0; i < num_pages; i++) {
            phys_reg->page_list[i] = (struct mapped_page *)kmalloc(sizeof(struct mapped_page), GFP_KERNEL);
        }
    }

    PrintDebug("mem_allocate allocate mem for phys_reg\n");
    for (i = 0; i < num_pages; i++) {

        paddr = node_allocate(state, alloc_pages);
       
        if (paddr <= 0) {
            PrintError("Could not allocate memory!\n");
            PrintError("Requested %llu pages, but only %llu are available\n", alloc_pages,
               hpmmap_check_pages(-1));

            ret = -ENOMEM;
            goto err;
        }

        if (reg) {
            phys_reg->page_list[i]->paddr  = paddr;
            phys_reg->page_list[i]->size   = page_size;
            phys_reg->page_list[i]->hpmmap = 1;
        }

        if (map_pages(state->pgd, vaddr, paddr, 1, page_size, alloc_reg->pg_prot) == 0) {
            PrintError("Could not map page from VA %p to PA %p\n", (void *)vaddr, (void *)paddr);
   
            ret = -EFAULT;
            goto err;
        }

        vaddr += (uintptr_t)page_size;
    }

    PrintDebug("mem_allocate return\n");
    if (reg) {
        *reg = phys_reg;
    }

    return 0;

 err:

    for (vaddr -= (uintptr_t)page_size, i--; 
         vaddr >= start; 
         vaddr -= (uintptr_t)page_size, i--)
    {

        unmap_page_and_free(state->pgd, vaddr);

        if (reg) {
            kfree(phys_reg->page_list[i]);
        }
    }

    if (reg) {
        kfree(phys_reg->page_list);
        kfree(phys_reg);
    }

    return ret;
}

/*
 * Function:    Deallocate memory backing the region specified in alloc_reg
 *
 * state:       Process' HPMMAP state
 * alloc_reg:   Virtual address region to be free'd
 *
 * Returns:     4KB pages free'd on success, < 0 otherwise
 */
int 
mem_deallocate(struct memory_state        * state, 
               struct allocated_vaddr_reg * alloc_reg) 
{
    uintptr_t vaddr = 0;
    u64 num_freed   = 0;
    u64 total_freed = 0;
    u64 start       = 0;
    u64 len         = 0;

    start = alloc_reg->start;
    len   = alloc_reg->end - start;

    if ((state->deallocating == 0) && 
        (alloc_reg->policy   == MEM_PERSIST)) {
        return 0;
    }

    for (vaddr  = (uintptr_t)start; 
         vaddr  < (uintptr_t)(start + len); 
         vaddr += (uintptr_t)(num_freed * PAGE_SIZE_4KB))
    {
        
        num_freed    = unmap_page_and_free(state->pgd, vaddr);
        total_freed += num_freed;

        if (num_freed == 0) {
            PrintError("Could not unmap page (VA: %p)\n", (void *)vaddr);
            return -EFAULT;
        }
    }

    // Success
    return total_freed;
}

/*
 * Function:    Map the physical memory region given in phys_reg
 *
 * state:       Process' HPMMAP state
 * phys_reg:    Physical address region to be mapped
 *
 * Returns:     0 on success, < 0 otherwise
 */
int 
mem_map_region(
           struct memory_state        * state, 
           struct allocated_vaddr_reg * alloc_reg,
           struct paddr_reg           * phys_reg) 
{
    struct mapped_page ** page_list = NULL;
    struct mapped_page  * page      = NULL;

    uintptr_t vaddr = 0;
    uintptr_t paddr = 0;

    u64 start     = 0;
    u64 page_size = 0;
    u64 i         = 0;
    int ret       = 0;

    page_list = phys_reg->page_list;
    start     = alloc_reg->start;

    for (i  = 0, vaddr  = (uintptr_t)start;
         i  < phys_reg->num_pages; 
         i += 1, vaddr += (uintptr_t)page_size) 
    {
        page      = page_list[i];
        paddr     = page->paddr;
        page_size = page->size;

        if (map_pages(state->pgd, vaddr, paddr, 1, page_size, alloc_reg->pg_prot) == 0) {
            PrintError("Could not map page from VA %p to PA %p\n", (void *)vaddr, (void *)paddr);
            ret = -EFAULT;
            goto err;
        }
    }

    // Success
    return 0;

 err:
    for (vaddr -= (uintptr_t)page_size, i--; 
         vaddr >= start; 
         vaddr -= (uintptr_t)page_size, i--)
    {
        page = page_list[i];
        page_size = page->size;
        unmap_page(state->pgd, vaddr, 0);
    }

    return ret;
}

/*
 * Function:    Map the physical memory region given in alloc_reg
 *
 * state:       Process' HPMMAP state
 * alloc_reg:   Virtual address region to be un-mapped
 *
 * Returns:     0 on success, < 0 otherwise
 */
int 
mem_unmap_region(struct memory_state        * state, 
                 struct allocated_vaddr_reg * alloc_reg) 
{
    uintptr_t vaddr = 0;
    u64 num_freed   = 0;
    u64 total_freed = 0;
    u64 start       = 0;
    u64 len         = 0;

    start = alloc_reg->start;
    len   = alloc_reg->end - start;

    for (vaddr  = (uintptr_t)start; 
         vaddr  < (uintptr_t)(start + len);
         vaddr += (uintptr_t)(num_freed * PAGE_SIZE_4KB))
    {
        num_freed    = unmap_page(state->pgd, vaddr, 0);
        total_freed += num_freed;

        if (num_freed == 0) {
            PrintError("Could not unmap page (VA: %p)\n", (void *)vaddr);
            return -EFAULT;
        }
    }

    // Success
    return total_freed;
}

char *
mem_policy_to_str(mem_policy_t policy) 
{
    switch (policy) {
        case MEM_NONE:
            return "NONE";
        case MEM_PERSIST:
            return "PERSISTENT";
        default:
            return "UNKNOWN";
    }
}

static uintptr_t 
node_allocate(struct memory_state * state, 
              u64                   num_pages) 
{
    return hpmmap_alloc_pages_on_node(num_pages, -1);
}

