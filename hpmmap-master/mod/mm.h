/*
 * Wrappers for interface with the buddy allocator, and other miscellaneous
 * stuff.
 *
 * (c) Brian Kocoloski <briankoco@cs.pitt.edu>, 2013
 *
 */


#ifndef _MM_H
#define _MM_H

#include <linux/mm.h>

/* 
 * Policies for the memory manager 
 */
typedef enum mem_policy {
    MEM_NONE,
    MEM_PERSIST
} mem_policy_t;



/* 
 * Maintain brk state
 */
struct brk_state {
    uintptr_t                    brk_base;   /* base address of the heap */
    uintptr_t                    brk;        /* current break value */
 
    struct list_head             alloc_list; /* List of all allocated vaddr regions */

    struct allocated_vaddr_reg * last;       /* Pointer to last guy */

};


/*
 * Maintain mmap state
 */
struct mmap_state {
    uintptr_t                   mmap_base;  /* base address of anon mmap region */
    uintptr_t                   mmap_max;   /* max anon region */

    struct list_head            free_list;  /* List of all free regions */
    struct list_head            alloc_list; /* List of all allocated regions */
};


/*
 * Per-process memory state
 */
struct memory_state {
    struct mutex        mutex;      /* state mutex */

    pid_t               pid;        /* pid for this state */
    atomic_t            ref_count;  /* number of references to this state */

    uintptr_t           pgd;        /* top level page table */
    struct brk_state  * brk_state;  /* brk */
    struct mmap_state * mmap_state; /* mmap */
    struct hashtable  * file_map;   /* list of shared mmap'd files */

    unsigned char initialized;      /* Is process memory map initialized */
    unsigned char preallocated;     /* Has process been preallocated? */
    unsigned char deallocating;     /* Is process being torn down */
};


struct mapped_page {
    u64 paddr;
    u64 size;
    int hpmmap;                     /* Was this allocated from an HPMMAP pool? */
};


struct paddr_reg {
    struct mapped_page ** page_list;
    u64                   num_pages;
};


/*
 *  Regions for virtual address mappings
 */
struct vaddr_reg {
    u64                          start;
    u64                          end;

    /* mmap information */
    unsigned long                mmap_flags;
    unsigned long                mmap_pgoff;
    unsigned long                mmap_fd;
    struct file                * mmap_file;

    /* two alloc region pointers - both can be needed for SHARED mappings
     * that exceed the size of the backing file */
    struct allocated_vaddr_reg * alloc_reg;

    struct list_head             node;
};


/*
 * Regions for allocated memory areas
 */
struct allocated_vaddr_reg {
    u64                start;
    u64                end;

    unsigned long      pg_prot;     /* Page table attributes */

    struct list_head   node;        /*  Each is maintained in a memory_state         */
    struct list_head   vaddr_list;  /*  Each maintains a list of allocated regions   */

    struct paddr_reg * phys_reg;    /* Finally, we also maintain a pointer to the physical memory
                                     *     structure
                                     */ 

    mem_policy_t       policy;      /* Memory allocation policy */
};






/* 
 *  Allocate memory to back the region specified in alloc_reg
 */
int 
mem_allocate(struct memory_state        * state, 
             struct allocated_vaddr_reg * alloc_reg,
             u64                          page_size,
             struct paddr_reg          ** reg);



/* 
 *  Deallocate memory backing the region specified in alloc_reg
 */
int 
mem_deallocate(struct memory_state        * state, 
               struct allocated_vaddr_reg * alloc_reg);


/* 
 * Map the physical memory region given in alloc_reg
 */
int 
mem_map_region(struct memory_state        * state, 
               struct allocated_vaddr_reg * alloc_reg,
               struct paddr_reg           * phys_reg);

/* 
 * Unmap the physical memory region given in alloc_reg 
 */
int 
mem_unmap_region(struct memory_state        * state, 
                 struct allocated_vaddr_reg * alloc_reg);


char * 
mem_policy_to_str(mem_policy_t policy);

#endif /* _MM_H */
