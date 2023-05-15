#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>

#include "hpmmap.h"
#include "hpmmap_syms.h"
#include "probe.h"

static int err;

void (*tlb_finish_mmu_fn)(struct mmu_gather * tlb);
void (*tlb_flush_mmu_fn)(struct mmu_gather * tlb);
void (*tlb_gather_mmu_fn)(struct mmu_gather * tlb, struct mm_struct *);

void tlb_gather_mmu(struct mmu_gather * tlb, 
                    struct mm_struct  * mm)
{
    return tlb_gather_mmu_fn(tlb, mm);
}

void tlb_finish_mmu(struct mmu_gather * tlb)
{
    return tlb_finish_mmu_fn(tlb);
}

void tlb_flush_mmu(struct mmu_gather * tlb)
{
    return tlb_flush_mmu_fn(tlb);
}


int
hpmmap_linux_symbol_init(void)
{
    unsigned long symbol_addr = 0;

    /* Symbol:
     * --  tlb_gather_mmu
     */
    {
        err = kallsyms_lookup_name_fn("tlb_gather_mmu", &symbol_addr);

        if (symbol_addr == 0) {
            PrintError("Linux symbol tlb_gather_mmu not found.\n");
            return -1;
        }

        tlb_gather_mmu_fn = (void (*)(struct mmu_gather *, struct mm_struct *))symbol_addr;
    }


    /* Symbol:
     * --  tlb_finish_mmu
     */
    {
        err = kallsyms_lookup_name_fn("tlb_finish_mmu", &symbol_addr);

        if (symbol_addr == 0) {
            PrintError("Linux symbol tlb_finish_mmu not found.\n");
            return -1;
        }

        tlb_finish_mmu_fn = (void (*)(struct mmu_gather *))symbol_addr;
    }

    /* Symbol:
     * --  tlb_flush_mmu
     */
    {
        err = kallsyms_lookup_name_fn("tlb_flush_mmu", &symbol_addr);

        if (symbol_addr == 0) {
            PrintError(KERN_ERR "Linux symbol tlb_flush_mmu not found.\n");
            return -1;
        }

        tlb_flush_mmu_fn = (void (*)(struct mmu_gather *))symbol_addr;
    }

    return 0;
}
