# Updated Made to Package

## Changes from Linux Kernel 4.x to 5.19

1. PDE_DATA() changed to pde_data() for Linux Kernel Version 5.17.0 or higher
2. updated zone_proc_ops to be of type static struct proc_ops for Linux Kernel Version 5.6.0 or higher
3. Added flush_tlb_mm_range definition in to mmap.c before calling #include <asm/tlb.h>
4. 