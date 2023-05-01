/*
 * HPMMAP main include
 *
 * (c) Brian Kocoloski <briankoco@cs.pitt.edu>, 2014
 * (c) Jack Lange <jacklange@cs.pitt.edu>, 2014
 *
 */

#ifndef _HPMMAP_H
#define _HPMMAP_H



/****** You may modify the following values to change the behavior of HPMMAP ******/

/* Page sizes used for the heap (BRK_PAGE_SIZE) and anonymous address ranges
 * (MMAP_PAGE_SIZE). Valid values are PAGE_SIZE_{4KB/2MB/1GB} 
 */

//#define BRK_PAGE_SIZE PAGE_SIZE_4KB
//#define MMAP_PAGE_SIZE PAGE_SIZE_4KB
#define BRK_PAGE_SIZE  PAGE_SIZE_2MB
#define MMAP_PAGE_SIZE PAGE_SIZE_2MB
//#define BRK_PAGE_SIZE PAGE_SIZE_1GB
//#define MMAP_PAGE_SIZE PAGE_SIZE_1GB


/* Amount of memory (in bytes) to preallocate and map at application launch for
 * processes using HPMMAP. For large-scale applications, preallocating and
 * mapping memory helps synchronize overheads across application ranks.
 *
 * If you're not sure, leave these at 0
 */
#define BRK_PREALLOCATE  0
#define MMAP_PREALLOCATE 0
//#define BRK_PREALLOCATE (1LL << 28)
//#define MMAP_PREALLOCATE (1LL << 30)

/* Enable debugging output in the kernel logs (dmesg) by uncommenting this line */
// #define DEBUG

/* Maximum sizes for anonymous mmap region */
/* 128 GB for mmap */
#define MMAP_MAX (1ULL << 37)


/******             Do not modify anything below this line                   ******/




/* MMAP_MAX GB of virtual address space, that will hopefully be unused.

   Note that this could be a serious issue, because this range is not reserved.
   If we find that this is problematic in the future, we can look at creating an
   "empty" VMA to prevent Linux from allocating anything here.

   Based on my thorough investigation (running `cat /proc/self/maps` ~20 times), 
   this appears to sit between the heap and runtime libraries
*/
#define MMAP_REGION_START     0x1000000000LL
#define MMAP_REGION_END       (MMAP_REGION_START + MMAP_MAX)

#define MMAP_PAGE_SIZE_SHARED PAGE_SIZE_4KB

#ifdef DEBUG
# define PrintDebug(fmt, args...) printk("HPMMAP (debug): " fmt, ## args)
#else
# define PrintDebug(fmt, args...) do {} while(0)
#endif

#define PrintError(fmt, args...) do {\
    printk("HPMMAP (error at %s:%d): %s: ", __FILE__, __LINE__, __func__);\
    printk(fmt, ## args);\
} while(0)

#include <linux/types.h>

// Returns the current CR3 value
static inline uintptr_t 
get_cr3(void)
{
    u64 cr3 = 0;

    __asm__ __volatile__ ("movq %%cr3, %0; "
          : "=q"(cr3)
          :
    );

    return (uintptr_t)cr3;
}


static inline void 
invlpg(uintptr_t page_addr)
{
    __asm__ __volatile__ ("invlpg (%0); "
          : 
          :"r"(page_addr)
          : "memory"
    );
}


#define numa_num_nodes()                num_online_nodes()
#define numa_addr_to_node(phys_addr)    page_to_nid(pfn_to_page(phys_addr >> PAGE_SHIFT))
#define numa_cpu_to_node(cpu_id)        cpu_to_node(cpu_id)
#define numa_get_distance(node1, node2) node_distance(node1, node2)

/* 
 * Page allocation functions
 */
uintptr_t 
hpmmap_alloc_pages(u64 num_pages);

uintptr_t 
hpmmap_alloc_pages_on_node(u64 num_pages, int numa_node);

/* 
 * Returns amount of available HPMMAP memory in a NUMA zone
 * 
 * numa_node
 *       %ul: NUMA zone to check 
 *        -1: NUMA zone bound to this CPU
 *        
 */
unsigned long long 
hpmmap_check_pages(int numa_node);

/* 
 * Free contiguous HPMMAP pages
 */
void hpmmap_free_pages(uintptr_t page_addr, 
                       u64 num_pages);

#endif /* _HPMMAP_H */
