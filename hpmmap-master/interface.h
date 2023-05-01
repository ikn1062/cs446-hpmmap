/* 
 * HPMMAP control utility
 * (c) Jack Lange, 2014
 * (c) Brian Kocoloski, 2014
*/

#ifndef _INTERFACE_H
#define _INTERFACE_H

#define DEV_FILENAME      "hpmmap"
#define PROC_DIR          "hpmmap"
#define PROC_MEM_FILENAME "mm"

struct memory_range {
    unsigned long long base_addr;
    unsigned long long pages;
    int node_id;
} __attribute__((packed));

// IOCTLs
#define ADD_MEMORY     50
#define RELEASE_MEMORY 51

#define REGISTER_PID   60
#define DEREGISTER_PID 61


#endif /* _INTERFACE_H */
