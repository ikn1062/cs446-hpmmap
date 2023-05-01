#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>

#include "hpmmap.h"
#include "hpmmap_syms.h"


void (*tlb_finish_mmu_fn)(struct mmu_gather * tlb, unsigned long start, unsigned long end);
void (*tlb_flush_mmu_fn)(struct mmu_gather * tlb, unsigned long start, unsigned long end);
void (*tlb_gather_mmu_fn)(struct mmu_gather * tlb, struct mm_struct *, unsigned long start, unsigned long end);

void tlb_gather_mmu(struct mmu_gather * tlb, 
                    struct mm_struct  * mm,
                    unsigned long       start, 
                    unsigned long       end)
{
    return tlb_gather_mmu_fn(tlb, mm, start, end);
}

void tlb_finish_mmu(struct mmu_gather * tlb, 
                    unsigned long       start, 
                    unsigned long       end)
{
    return tlb_finish_mmu_fn(tlb, start, end);
}

void tlb_flush_mmu(struct mmu_gather * tlb, 
                   unsigned long       start, 
                   unsigned long       end)
{
    return tlb_flush_mmu_fn(tlb, start, end);
}


int
hpmmap_linux_symbol_init(void)
{
    unsigned long symbol_addr = 0;

    /* Symbol:
     * --  tlb_gather_mmu
     */
    {
        symbol_addr = kallsyms_lookup_name("tlb_gather_mmu");

        if (symbol_addr == 0) {
            PrintError("Linux symbol tlb_gather_mmu not found.\n");
            return -1;
        }

        tlb_gather_mmu_fn = (void (*)(struct mmu_gather *, struct mm_struct *, unsigned long, unsigned long))symbol_addr;
    }


    /* Symbol:
     * --  tlb_finish_mmu
     */
    {
        symbol_addr = kallsyms_lookup_name("tlb_finish_mmu");

        if (symbol_addr == 0) {
            PrintError("Linux symbol tlb_finish_mmu not found.\n");
            return -1;
        }

        tlb_finish_mmu_fn = (void (*)(struct mmu_gather *, unsigned long, unsigned long))symbol_addr;
    }

    /* Symbol:
     * --  tlb_flush_mmu
     */
    {
        symbol_addr = kallsyms_lookup_name("tlb_flush_mmu");

        if (symbol_addr == 0) {
            PrintError(KERN_ERR "Linux symbol tlb_flush_mmu not found.\n");
            return -1;
        }

        tlb_flush_mmu_fn = (void (*)(struct mmu_gather *, unsigned long, unsigned long))symbol_addr;
    }

    return 0;
}
