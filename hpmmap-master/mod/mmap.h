/*
 * Interface to system call management code. The bulk of the memory management
 * work is in the associated .c file (mmap.c)
 *
 * (c) Brian Kocoloski <briankoco@cs.pitt.edu>, 2013
 *
 */

#ifndef _MMAP_H
#define _MMAP_H

#include <asm/types.h>

int 
hook_mmap_syscalls(void);

int 
unhook_mmap_syscalls(void);

int
register_process(u32 pid);

int
unmap_process(u32 pid);

int 
register_process_clone(u32 parent_pid, 
                       u32 clone_pid);

int 
hpmmap_check_user_pages(u32           pid, 
                        unsigned long addr, 
                        unsigned long nr_pages);

long
hpmmap_get_user_pages(u32                      pid, 
                      unsigned long            addr, 
                      unsigned long            nr_pages,
                      struct page           ** pages,
                      struct vm_area_struct ** vmas,
                      int                      flush);

int 
hpmmap_check_pfn_range(u32           pid,
                       unsigned long addr,
                       unsigned long pfn,
                       unsigned long size);

int 
hpmmap_remap_pfn_range(u32           pid,
                       unsigned long addr,
                       unsigned long pfn,
                       unsigned long size,
                       unsigned long page_prot);
                
                

#endif /* _MMAP_H */
