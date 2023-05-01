/*
 * Page table management code
 *
 * (c) Jack Lange <jacklange@cs.pitt.edu>, 2012
 * (c) Brian Kocoloski <briankoco@cs.pitt.edu>, 2013
 *
 */
#ifndef _MAPPER_H
#define _MAPPER_H

#include <linux/module.h>
#include <linux/rbtree.h>

uintptr_t
walk_pts(uintptr_t   pgd,
         uintptr_t   vaddr,
         uintptr_t * offset,
         u64       * page_size);

uintptr_t
map_pages(uintptr_t pgd,
          uintptr_t vaddr, 
          uintptr_t paddr, 
          u64       num_pages, 
          u64       page_size,
          u64       prot);

u64 
unmap_page(uintptr_t pgd,
           uintptr_t vaddr, 
           int free);

u64
unmap_page_and_free(uintptr_t pgd,
                    uintptr_t vaddr);

u64 
mapped_size(uintptr_t pgd,
            uintptr_t vaddr);

#endif /* _MAPPER_H */
