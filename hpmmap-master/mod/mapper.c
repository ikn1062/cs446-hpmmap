#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mman.h>

#include "hpmmap.h"
#include "mapper.h"
#include "pgtables.h"


static void 
set_page_flags(pte64_t * pt, 
               u64       prot)
{
    pt->user_page         = 1;
    pt->present           = 1;


    if (prot & PROT_WRITE) {
        pt->writable      = 1;
    }

    if (!(prot & PROT_EXEC)) {
        pt->no_execute    = 1;
    }

    if (prot & _PAGE_CACHE_UC_MINUS) {
        pt->cache_disable = 1;
    }

    if (prot & _PAGE_CACHE_WC) {
        pt->write_through = 1;
    }
}



uintptr_t
walk_pts(uintptr_t   pgd,
         uintptr_t   vaddr,
         uintptr_t * offset, 
         u64       * page_size)
{
    //uintptr_t cr3 = get_cr3();
    //pml4e64_t * pml = CR3_TO_PML4E64_VA(cr3);
    pml4e64_t * pml = (pml4e64_t *)pgd;
    pdpe64_t * pdp  = NULL;
    pde64_t * pd    = NULL;
    pte64_t * pt    = NULL;
    
    pml4e64_t * pml_entry = NULL;
    pdpe64_t * pdp_entry  = NULL;
    pde64_t * pd_entry    = NULL;
    pte64_t * pt_entry    = NULL;

    pdpe64_1GB_t * large_pdp_entry = NULL;
    pde64_2MB_t * large_pd_entry   = NULL;

    // Backing pade address
    uintptr_t page_addr = 0;
    
    //PrintDebug("Walking page table VA=%p (pml=%p)\n", (void *)vaddr, pml);

    pml_entry = &pml[PML4E64_INDEX(vaddr)];

    if (!pml_entry->present) {
        PrintDebug("PDP Not present (idx = %llu)\n", PML4E64_INDEX(vaddr));
        return (uintptr_t)NULL;
    } else {
        pdp = __va(BASE_TO_PAGE_ADDR(pml_entry->pdp_base_addr));
    }

    pdp_entry = &pdp[PDPE64_INDEX(vaddr)];

    if (!pdp_entry->present) {
        PrintDebug("PD not present (idx = %llu)\n", PDPE64_INDEX(vaddr));
        return (uintptr_t)NULL;
    } else {
        if (pdp_entry->large_page) {
            large_pdp_entry = (pdpe64_1GB_t *)pdp_entry;

            // No PD or PT
            page_addr  = BASE_TO_PAGE_ADDR_1GB(large_pdp_entry->page_base_addr);
//            PrintDebug("Backing page AT %p\n", __va(page_addr));

            *offset    = PAGE_OFFSET_1GB(vaddr);
            *page_size = PAGE_SIZE_1GB;
            return page_addr;
        }

        pd = __va(BASE_TO_PAGE_ADDR(pdp_entry->pd_base_addr));
    }
    
    pd_entry = &pd[PDE64_INDEX(vaddr)];

    if (!pd_entry->present) {
        PrintDebug(" PT not present (idx = %llu)\n", PDE64_INDEX(vaddr));
        return (uintptr_t)NULL;
    } else {
        if (pd_entry->large_page) {
            large_pd_entry = (pde64_2MB_t *)pd_entry;

            // No PT
            page_addr  = BASE_TO_PAGE_ADDR_2MB(large_pd_entry->page_base_addr);
            //PrintDebug("Backing page AT %p\n", __va(page_addr));

            *offset    = PAGE_OFFSET_2MB(vaddr);
            *page_size = PAGE_SIZE_2MB;
            return page_addr;
        }

        pt       = __va(BASE_TO_PAGE_ADDR(pd_entry->pt_base_addr));
        pt_entry = &pt[PTE64_INDEX(vaddr)];
        
        if (!pt_entry->present) {
            PrintDebug("Not present backing page (idx=%llu)\n", PTE64_INDEX(vaddr));
            return (uintptr_t)NULL;
        } else {
            page_addr = BASE_TO_PAGE_ADDR(pt_entry->page_base_addr);
            //PrintDebug("Backing page (idx = %llu) AT %p\n", PTE64_INDEX(vaddr), __va(page_addr));

            *offset    = 0;
            *page_size = PAGE_SIZE_4KB;
            return page_addr;
        }
    }
}

uintptr_t
map_pages(uintptr_t pgd,
          uintptr_t vaddr, 
          uintptr_t paddr, 
          u64       num_pages, 
          u64       page_size,
          u64       prot) 
{
    //uintptr_t cr3 = get_cr3();
    //pml4e64_t * pml = CR3_TO_PML4E64_VA(cr3);
    pml4e64_t    * pml             = (pml4e64_t *)pgd;
    pdpe64_t     * pdp             = NULL;
    pde64_t      * pd              = NULL;
    pte64_t      * pt              = NULL;

    pml4e64_t    * pml_entry       = NULL;
    pdpe64_t     * pdp_entry       = NULL;
    pde64_t      * pd_entry        = NULL;
    pte64_t      * pt_entry        = NULL;

    pde64_2MB_t  * large_pd_entry  = NULL;
    pdpe64_1GB_t * large_pdp_entry = NULL;

    int pml_idx = 0;
    int pdp_idx = 0;
    int pd_idx  = 0;
    int pt_idx  = 0;

    u64 offset  = 0;

    /*
    PrintDebug("Mapping %llu (%s) pages from VADDR=%p to PADDR=%p\n",   
           num_pages, 
           (page_size == PAGE_SIZE_4KB) ? "4KB" : 
           (page_size == PAGE_SIZE_2MB) ? "2MB" : "1GB",
           (void *)vaddr, 
           (void *)paddr
           );
    */

    for (pml_idx = PML4E64_INDEX(vaddr + offset); 
         (num_pages > 0) && (pml_idx < 512); 
         pml_idx++)
    {

        pml_entry = &pml[pml_idx];

        if (!pml_entry->present) {
            // Allocate a page and map it in
            uintptr_t pdp_page = (uintptr_t)hpmmap_alloc_pages(1);
            //printk("PDP not present (idx = %llu)\n", PML4E64_INDEX(vaddr + offset));

            pdp = __va(pdp_page);
            memset(pdp, 0, PAGE_SIZE_4KB);

            pml_entry->pdp_base_addr = PAGE_TO_BASE_ADDR(pdp_page);
            set_page_flags((pte64_t *)pml_entry, PROT_WRITE);
        } else {
            //printk("Found PDP (idx = %llu)\n", PML4E64_INDEX(vaddr + offset));
            pdp = __va(BASE_TO_PAGE_ADDR(pml_entry->pdp_base_addr));
        }

        // 1 GB huge pages
        if (page_size == PAGE_SIZE_1GB) {
            for (pdp_idx = PDPE64_INDEX(vaddr + offset);
                (num_pages > 0) && (pdp_idx < 512);
                num_pages--, pdp_idx++, offset += PAGE_SIZE_1GB)
            {

                pdp_entry       = &pdp[pdp_idx];
                large_pdp_entry = (pdpe64_1GB_t *)pdp_entry;

                if (!pdp_entry->present) {
                    large_pdp_entry->page_base_addr = PAGE_TO_BASE_ADDR_1GB(paddr + offset);
                    large_pdp_entry->large_page     = 1;
                    set_page_flags((pte64_t *)large_pdp_entry, prot);

                    //printk("Setting Huge (1GB) PDP entry(%p) (idx = %d) for %p to %p\n",
                    //    large_pdp_entry, pdp_idx, (void *)(vaddr + offset),
                    //    (void *)BASE_TO_PAGE_ADDR_1GB(large_pdp_entry->page_base_addr));
                } else {
                    PrintError("Found a page already mapped to the target region.\n"
                        "\toffset = %llu\n"
                        "\ttarget VADDR = %p\n"
                        "\tbase addr = %p, idx = %d\n"
                        "\tCurrently mapped paddr = %p\n"
                        "\twr=%d, user=%d, global=%d, large_page=%d\n",
                        offset,
                        (void *)(vaddr + offset),
                        (void *)vaddr, pdp_idx,
                        (void *)BASE_TO_PAGE_ADDR_1GB(large_pdp_entry->page_base_addr),
                        large_pdp_entry->writable,
                        large_pdp_entry->user_page,
                        large_pdp_entry->global_page,
                        large_pdp_entry->large_page
                   );

                    return 0;
                }

            }

            // Huge pages finished
            return vaddr;
        }
        
        // Not 1GB pages
        for (pdp_idx = PDPE64_INDEX(vaddr + offset);
            (num_pages > 0) && (pdp_idx < 512);
            pdp_idx++)
        {

            pdp_entry = &pdp[pdp_idx];

            if (!pdp_entry->present) {
                uintptr_t pd_page = (uintptr_t)hpmmap_alloc_pages(1);
                //printk("PD not present (idx = %llu)\n", PDPE64_INDEX(vaddr + offset));

                pd = __va(pd_page);
                memset(pd, 0, PAGE_SIZE_4KB);

                pdp_entry->pd_base_addr = PAGE_TO_BASE_ADDR(pd_page);
                set_page_flags((pte64_t *)pdp_entry, prot);
            } else {
                //printk("Found PD (idx = %llu)\n", PDPE64_INDEX(vaddr + offset));
                pd = __va(BASE_TO_PAGE_ADDR(pdp_entry->pd_base_addr));
            }

            // 2 MB large pages
            if (page_size == PAGE_SIZE_2MB) {
                for (pd_idx = PDE64_INDEX(vaddr + offset);
                    (num_pages > 0) && (pd_idx < 512);
                    num_pages--, pd_idx++, offset += PAGE_SIZE_2MB)
                {
                        
                    pd_entry       = &pd[pd_idx];
                    large_pd_entry = (pde64_2MB_t *)pd_entry;

                    if (!pd_entry->present) {
                        large_pd_entry->page_base_addr = PAGE_TO_BASE_ADDR_2MB(paddr + offset);
                        large_pd_entry->large_page     = 1;
                        set_page_flags((pte64_t *)large_pd_entry, prot);

                        //printk("Setting Large (2MB) PD entry(%p) (idx = %d) for %p to %p\n",
                        //    large_pd_entry, pd_idx, (void *)(vaddr + offset),
                        //   (void *)BASE_TO_PAGE_ADDR_2MB(large_pd_entry->page_base_addr)
                        //);
                    } else {
                        PrintError("Found a page already mapped to the target region.\n"
                            "\toffset = %llu\n"
                            "\ttarget VADDR = %p\n"
                            "\tbase addr = %p, idx = %d\n"
                            "\tCurrently mapped paddr = %p\n"
                            "\twr=%d, user=%d, global=%d, large_page=%d\n",
                            offset,
                            (void *)(vaddr + offset),
                            (void *)vaddr, pdp_idx,
                            (void *)BASE_TO_PAGE_ADDR_2MB(large_pd_entry->page_base_addr),
                            large_pd_entry->writable,
                            large_pd_entry->user_page,
                            large_pd_entry->global_page,
                            large_pd_entry->large_page
                        );

                        return 0;
                    }
                }

                // Large pages finished
                return vaddr;
            }

            // 4 KB small pages
            for (pd_idx = PDE64_INDEX(vaddr + offset);
                (num_pages > 0) && (pd_idx < 512);
                pd_idx++)
            {

                pd_entry = &pd[pd_idx];

                if (!pd_entry->present) {
                    uintptr_t pt_page = (uintptr_t)hpmmap_alloc_pages(1);
                    //printk("PT not present (idx = %llu)\n", PDE64_INDEX(vaddr + offset));

                    pt = __va(pt_page);
                    memset(pt, 0, PAGE_SIZE_4KB);

                    pd_entry->pt_base_addr = PAGE_TO_BASE_ADDR(pt_page);
                    set_page_flags((pte64_t *)pd_entry, prot);
                } else {
                    //printk("Found PT (idx = %llu)\n", PDE64_INDEX(vaddr + offset));
                    pt = __va(BASE_TO_PAGE_ADDR(pd_entry->pt_base_addr));
                }

                for (pt_idx = PTE64_INDEX(vaddr + offset);
                    (num_pages > 0) && (pt_idx < 512);
                    num_pages--, pt_idx++, offset += PAGE_SIZE_4KB)
                {

                    pt_entry = &pt[pt_idx];

                    // NOTE: Really strange. Sometimes there is a NULL page (physical address 0)
                    // mapped in. Currently just ignoring it and mapping like it's not there
                    if (!(pt_entry->present) || 
                        !(BASE_TO_PAGE_ADDR(pt_entry->page_base_addr)))
                    {
                        pt_entry->page_base_addr = PAGE_TO_BASE_ADDR(paddr + offset);
                        set_page_flags((pte64_t *)pt_entry, prot);

                        //printk("Setting PT entry (backing page) (%p) (idx = %d) for %p to %p\n",
                        //    pt_entry, pt_idx, (void *)(vaddr + offset),
                        //    (void *)BASE_TO_PAGE_ADDR(pt_entry->page_base_addr)
                        //);
                    } else {
                        PrintError("Found a page already mapped to the target region.\n"
                            "\toffset = %llu\n"
                            "\ttarget VADDR = %p\n"
                            "\tbase addr = %p, idx = %d\n"
                            "\tCurrently mapped paddr = %p\n"
                            "\twr=%d, user=%d, global=%d\n",
                            offset,
                            (void *)(vaddr + offset),
                            (void *)vaddr, pdp_idx,
                            (void *)BASE_TO_PAGE_ADDR(pt_entry->page_base_addr),
                            pt_entry->writable,
                            pt_entry->user_page,
                            pt_entry->global_page
                        );

                        return 0;
                    }
                }
            }
        }
    }

    return vaddr;
}

u64 unmap_page_and_free(uintptr_t pgd,
                        uintptr_t vaddr)
{
    return unmap_page(pgd, vaddr, 1);
}

/* Update: this function now returns the number of physical (4KB) pages that were free'd. */
u64 
unmap_page(uintptr_t pgd,
           uintptr_t vaddr, 
           int       free) 
{
    //uintptr_t cr3 = get_cr3();
    //pml4e64_t * pml = CR3_TO_PML4E64_VA(cr3);
    pml4e64_t * pml = (pml4e64_t *)pgd;
    pdpe64_t * pdp  = NULL;
    pde64_t * pd    = NULL;
    pte64_t * pt    = NULL;

    pml4e64_t * pml_entry = NULL;
    pdpe64_t * pdp_entry  = NULL;
    pde64_t * pd_entry    = NULL;
    pte64_t * pt_entry    = NULL;

    pde64_2MB_t * large_pd_entry   = NULL;
    pdpe64_1GB_t * large_pdp_entry = NULL;

    // Backing page address
    uintptr_t page_addr = 0;

    int i         = 0;
    u64 num_freed = 0;

    //printk("Unmapping page VA=%p (cr3 = %p) (pml=%p)\n", (void *)vaddr, (void *)cr3, pml); 

    pml_entry = &pml[PML4E64_INDEX(vaddr)];

    if (!pml_entry->present) {
        PrintDebug("Tried to free with PDP not present (idx = %llu)\n", PML4E64_INDEX(vaddr));
        return 0;
    }
    else {
        //printk("Found PDP (idx = %llu)\n", PML4E64_INDEX(vaddr));
        pdp = __va(BASE_TO_PAGE_ADDR(pml_entry->pdp_base_addr));
    }

    pdp_entry = &pdp[PDPE64_INDEX(vaddr)];

    if (!pdp_entry->present) {
        PrintDebug("Tried to free with PD not present (idx = %llu)\n", PDPE64_INDEX(vaddr));
        return 0;
    }

    if (pdp_entry->large_page) {
        large_pdp_entry = (pdpe64_1GB_t *)pdp_entry;
        page_addr       = BASE_TO_PAGE_ADDR_1GB(large_pdp_entry->page_base_addr);

        // No PD (or PT), so free backing pages from here
        if (free) {
            hpmmap_free_pages(page_addr, 512 * 512);
        }

        num_freed = 512 * 512;
        memset(large_pdp_entry, 0, sizeof(pdpe64_1GB_t));

        invlpg(PAGE_ADDR_4KB(vaddr));

        // Huge page free'd; don't walk through PD/PT
    }
    else {
        //printk("Found PD (idx = %llu)\n", PDPE64_INDEX(vaddr));
        pd       = __va(BASE_TO_PAGE_ADDR(pdp_entry->pd_base_addr));
        pd_entry = &pd[PDE64_INDEX(vaddr)];

        if (!pd_entry->present) {
            PrintDebug("Tried to free with PT not present (idx = %llu)\n", PDE64_INDEX(vaddr));
            return 0;
        }
        else {
            if (pd_entry->large_page) {
                large_pd_entry = (pde64_2MB_t *)pd_entry;
                page_addr      = BASE_TO_PAGE_ADDR_2MB(large_pd_entry->page_base_addr);

                // No PT, so free backing pages from here
                if (free) {
                    hpmmap_free_pages(page_addr, 512);
                }

                num_freed = 512;
                memset(large_pd_entry, 0, sizeof(pde64_2MB_t));

                invlpg(PAGE_ADDR_4KB(vaddr));
            }
            else {
                //printk("Found PT (idx = %llu)\n", PDE64_INDEX(vaddr));
                pt       = __va(BASE_TO_PAGE_ADDR(pd_entry->pt_base_addr));
                pt_entry = &pt[PTE64_INDEX(vaddr)];

                if (!pt_entry->present) {
                    PrintDebug("Tried to free not present backing page (idx = %llu)\n", PTE64_INDEX(vaddr));
                    return 0;
                }

                page_addr = BASE_TO_PAGE_ADDR(pt_entry->page_base_addr);

                if (free) {
                    hpmmap_free_pages(page_addr, 1);
                }

                num_freed = 1;
                memset(pt_entry, 0, sizeof(pte64_t));

                invlpg(PAGE_ADDR_4KB(vaddr));

                // Backtrack through pts, freeing if needed
                // Only 4KB page sizes go through pt entries
                for (i = 0; i < MAX_PTE64_ENTRIES; i++) {
                    pt_entry = &pt[i];

                    if (pt_entry->present) {
                        return num_freed;
                    }
                }

                // no more pages in this pt directory
                //printk("Freeing PT page\n");
                memset(pd_entry, 0, sizeof(pte64_t));
                hpmmap_free_pages(__pa(pt), 1);
            }
        }

        // 1GB pages don't go through pd entries
        for (i = 0; i < MAX_PDE64_ENTRIES; i++) {
            pd_entry = &pd[i];

            if (pd_entry->present) {
                return num_freed;
            }
        }

        // no more pages in this pd directory
        //printk("Freeing PD page\n");
        memset(pdp_entry, 0, sizeof(pdpe64_t));
        hpmmap_free_pages(__pa(pd), 1);
    }

    // All page sizes go through pdp entries
    for (i = 0; i < MAX_PDPE64_ENTRIES; i++) {
        pdp_entry = &pdp[i];

        if (pdp_entry->present) {
            return num_freed;
        }
    }

    // no more pages in this pt directory
    //printk("Freeing PDP page\n");
    memset(pml_entry, 0, sizeof(pml4e64_t));
    hpmmap_free_pages(__pa(pdp), 1);

    // Cannot free PML entry

    return num_freed;
}

/* Returns true if the size of the physical backing page for this vaddr is page_size */
static int
__mapped_size(uintptr_t          pgd,
              uintptr_t          vaddr,
              unsigned long long page_size) 
{
    //uintptr_t cr3 = get_cr3();
    //pml4e64_t * pml = CR3_TO_PML4E64_VA(cr3);
    pml4e64_t * pml = (pml4e64_t *)pgd;
    pdpe64_t * pdp  = NULL;
    pde64_t * pd    = NULL;
    pte64_t * pt    = NULL;
    
    pml4e64_t * pml_entry = NULL;
    pdpe64_t * pdp_entry  = NULL;
    pde64_t * pd_entry    = NULL;
    pte64_t * pt_entry    = NULL;

    pdpe64_1GB_t * large_pdp_entry = NULL;
    pde64_2MB_t * large_pd_entry   = NULL;

    // Backing pade address
    uintptr_t page_addr = 0;

    vaddr     = PAGE_ALIGN_DOWN(vaddr, page_size);
    pml_entry = &pml[PML4E64_INDEX(vaddr)];

    if (!pml_entry->present) {
        return 0;
    } else {
        pdp = __va(BASE_TO_PAGE_ADDR(pml_entry->pdp_base_addr));
    }

    pdp_entry = &pdp[PDPE64_INDEX(vaddr)];

    if (!pdp_entry->present) {
        return 0;
    } else {
        if (pdp_entry->large_page) {
            large_pdp_entry = (pdpe64_1GB_t *)pdp_entry;

            // No PD or PT
            page_addr  = BASE_TO_PAGE_ADDR_1GB(large_pdp_entry->page_base_addr);

            return (page_size == PAGE_SIZE_1GB);
        }

        pd = __va(BASE_TO_PAGE_ADDR(pdp_entry->pd_base_addr));
    }
    
    pd_entry = &pd[PDE64_INDEX(vaddr)];

    if (!pd_entry->present) {
        return 0;
    } else {
        if (pd_entry->large_page) {
            large_pd_entry = (pde64_2MB_t *)pd_entry;
            page_addr      = BASE_TO_PAGE_ADDR_2MB(large_pd_entry->page_base_addr);

            // No PT
            return (page_size == PAGE_SIZE_2MB);
        }

        pt       = __va(BASE_TO_PAGE_ADDR(pd_entry->pt_base_addr));
        pt_entry = &pt[PTE64_INDEX(vaddr)];
        
        if (!pt_entry->present) {
            return 0;
        } else {
            page_addr = BASE_TO_PAGE_ADDR(pt_entry->page_base_addr);
            return (page_size == PAGE_SIZE_4KB);
        }
    }
}

u64 
mapped_size(uintptr_t pgd,
            uintptr_t vaddr) 
{
    if (__mapped_size(pgd, vaddr, PAGE_SIZE_1GB)) {
        return PAGE_SIZE_1GB;
    }

    if (__mapped_size(pgd, vaddr, PAGE_SIZE_2MB)) {
        return PAGE_SIZE_2MB;
    }

    if (__mapped_size(pgd, vaddr, PAGE_SIZE_4KB)) {
        return PAGE_SIZE_4KB;
    }

    return 0;
}

