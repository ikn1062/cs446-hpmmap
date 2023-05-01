/*
 * HPMMAP memory control utility
 *
 * (c) Brian Kocoloski, 2014
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h> 
#include <unistd.h> 
#include <string.h>
#include <getopt.h>
#include <fcntl.h>

#include "pet_mem.h"
#include "../interface.h"


#define MODE_NONE        -1
#define MODE_STATUS       0
#define MODE_OFFLINE      1
#define MODE_ONLINE       2
#define MODE_POOL_OFFLINE 3
#define MODE_POOL_ONLINE  4

#define MAX_POOL_ORDER   30


#define SYS_PATH  "/sys/devices/system/memory/"
#define NUMA_PATH "/sys/devices/system/node/"

static void 
usage(char ** argv)
{
    printf("Usage: %s \n"
       "\t'-s': Print system memory status\n"
       "\t'[-n <numa_node>] [-a | -r] <num_blocks>': Add/Remove <num_blocks> blocks to/from HPMMAP [from numa node <numa_node>]\n"
       "\t'[-n <numa node>] [-A | -R] <pool_order>': Add/Remove 2^<pool_order> blocks to/from HPMMAP [from numa node <numa_node>]\n"
       , *argv
       );
}

static void 
hpmmap_add_memory(int                num_blocks, 
                  int                numa_zone, 
                  struct mem_block * block_arr) 
{
    struct memory_range mem;
    unsigned long long  block_size_bytes = pet_block_size();
    int fd = 0;

    fd = open("/dev/" DEV_FILENAME, O_RDWR);

    if (fd == -1) {
        perror("open");
        exit(-1);
    }

    mem.base_addr = block_arr[0].base_addr;
    mem.pages     = num_blocks * (block_size_bytes / 4096LL);
    mem.node_id   = numa_zone;

    if (ioctl(fd, ADD_MEMORY, &mem) == -1) {
        perror("Failed to add memory to HPMMAP");
        close(fd);
        exit(-1);
    }

    printf("Giving HPMMAP %lluMB of memory at (%p)\n",
       (mem.pages * 4096) / (1024 * 1024), mem.base_addr);

    close(fd);
}

static void 
hpmmap_remove_memory(int                num_blocks, 
                     int                numa_zone, 
                     struct mem_block * block_arr) 
{
    int fd = 0;
    struct memory_range mem;
    unsigned long long  block_size_bytes = pet_block_size();

    fd = open("/dev/" DEV_FILENAME, O_RDWR);

    if (fd == -1) {
        perror("open");
    }

    mem.pages   = num_blocks * (block_size_bytes / 4096LL);
    mem.node_id = numa_zone;

    if (ioctl(fd, RELEASE_MEMORY, &mem) == -1) {
        perror("Failed to remove memory from HPMMAP");
        close(fd);
    }

    close(fd);

    if (mem.pages > 0) {
        int i = 0;

        for (i = 0; i < num_blocks; i++) {
            block_arr[i].numa_node  = numa_zone;
            block_arr[i].base_addr  = mem.base_addr + (i * block_size_bytes);
            block_arr[i].pages      = block_size_bytes / 4096LL;
        }

        printf("Retrieved %lluMB of memory at (%p) from HPMMAP\n",
           (mem.pages * 4096) / (1024 * 1024), mem.base_addr);
    } else {
        block_arr[0].pages = 0;
    }
}

static int
hpmmap_offline_blocks(int num_blocks, 
                      int numa_zone) 
{
    unsigned long long block_size_bytes = pet_block_size();
    struct mem_block * block_arr        = NULL;
    int                offlined_blocks  = 0;

    int i   = 0;
    int ret = 0;

    block_arr = malloc(sizeof(struct mem_block) * num_blocks);

    if (!block_arr) {
        perror("malloc");
        return -1;
    }

    offlined_blocks = pet_offline_blocks(num_blocks, numa_zone, block_arr);

    if (offlined_blocks == -1) {
        printf("Failed to offline memory blocks from numa zone %d\n", numa_zone);
        free(block_arr);
        return -1;
    }
    
    for (i = 0; i < offlined_blocks; i++) { 
        hpmmap_add_memory(1, numa_zone, &(block_arr[i]));
    }

    free(block_arr);
    return offlined_blocks;
}

static int 
hpmmap_online_blocks(int num_blocks, 
                     int numa_zone) 
{
    unsigned long long block_size_bytes = pet_block_size();
    struct mem_block * block_arr        = NULL;
    int                onlined_blocks   = 0;
 
    int i   = 0;
    int ret = 0;
    
    block_arr = malloc(sizeof(struct mem_block) * num_blocks);

    if (!block_arr) {
        perror("malloc");
        return -1;
    }

    onlined_blocks = num_blocks;

    for (i = 0; i < num_blocks; i++) {

        hpmmap_remove_memory(1, numa_zone, &(block_arr[i]));

        if (block_arr[i].pages == 0) {
            onlined_blocks = i;
            break;
        }
    }

    ret = pet_online_blocks(onlined_blocks, block_arr);

    if (ret) {
        printf("Failed to online memory blocks to numa zone %d\n", numa_zone);
        free(block_arr);
        return -1;
    }

    free(block_arr);
    return onlined_blocks;
}


static int 
hpmmap_offline_pool(int pool_order, 
                    int numa_zone) 
{

    unsigned long long block_size_bytes = pet_block_size();
    unsigned long long contig_blocks    = 0;
    struct mem_block * block_arr        = NULL;

    int ret = 0;

    contig_blocks = (1ULL << pool_order) / block_size_bytes;
    block_arr     = malloc(sizeof(struct mem_block) * contig_blocks);

    if (!block_arr) {
        perror("malloc");
        return -1;
    }

    ret = pet_offline_contig_blocks(contig_blocks, numa_zone, (1ULL << pool_order), block_arr);

    if (ret) {
        printf("Failed to offline memory pool of order %d on numa zone %d\n",
           pool_order, numa_zone);

        free(block_arr);
        return -1;
    }

    hpmmap_add_memory(contig_blocks, numa_zone, block_arr);

    free(block_arr);
    return 0;
}

static int 
hpmmap_online_pool(int pool_order,
                   int numa_zone)
{
    unsigned long long block_size_bytes = pet_block_size();
    unsigned long long contig_blocks    = 0;
    struct mem_block * block_arr        = NULL;
    int ret = 0;

    contig_blocks = (1ULL << pool_order) / block_size_bytes;
    block_arr     = malloc(sizeof(struct mem_block) * contig_blocks);

    if (!block_arr) {
        perror("malloc");
        return -1;
    }

    hpmmap_remove_memory(contig_blocks, numa_zone, block_arr);

    if (block_arr[0].pages == 0) {
        printf("Failed to free memory pool of order %d on numa zone %d from HPMMAP\n",
           pool_order, numa_zone);

        free(block_arr);
        return -1;
    }

    ret = pet_online_blocks(contig_blocks, block_arr);

    if (ret) {
        printf("Failed to online memory pool of order %d on numa zone %d\n",
           pool_order, numa_zone);

        free(block_arr);
        return -1;
    }

    free(block_arr);
    return 0;
}

int 
main(int argc, 
     char ** argv) 
{
    int c           = 0;
    int num_blocks  = 0;    
    int numa_zone   = 0;
    int offlined    = 0;
    int onlined     = 0;
    int pool_order  = 0;
    static int mode = MODE_NONE;

    opterr = 0;

    while ((c = getopt(argc, argv, "n:aArRs")) != -1) {
        switch (c) {
            case 'n':
                numa_zone = atoi(optarg);
                break;

            case 'a':
                mode = MODE_OFFLINE;
                break;

            case 'A':
                mode = MODE_POOL_OFFLINE;
                break;

            case 'r':
                mode = MODE_ONLINE;
                break;

            case 'R':
                mode = MODE_POOL_ONLINE;
                break;

            case 's':
                mode = MODE_STATUS;
                break;

            default:
                usage(argv);
                return 0;
        }
    }

    if (mode == MODE_NONE) {
        usage(argv);
        return -1;
    } else if (mode == MODE_STATUS) {
        struct mem_block * block_arr  = NULL;
        unsigned int       num_blocks = 0;
        unsigned int       j          = 0;

        if (pet_mem_status(&num_blocks, &block_arr) != 0) {
            printf("Error: Could not get block status\n");
            return -1;
        }

        for (j = 0; j < num_blocks; j++) {
            printf("Block %d (Base addr=%p, NUMA=%d) Status=%s\n",
           j, (void *)block_arr[j].base_addr,
           block_arr[j].numa_node,
           pet_mem_state_to_str(block_arr[j].state));
        }

        return 0;
    } 

    if (optind != (argc - 1)) {
        usage(argv);
        return -1;
    }


    switch (mode) {
        case MODE_OFFLINE: {
            num_blocks = atoi(argv[optind]);
            offlined   = hpmmap_offline_blocks(num_blocks, numa_zone);

            if (offlined == -1) {
                printf("Error offlining %d blocks fron zone %d\n",
                    num_blocks, numa_zone);
            } else {
                printf("Offlined %d blocks out of %d requested from zone %d\n",
                    offlined, num_blocks, numa_zone);
            }
            break;
        }

        case MODE_POOL_OFFLINE: {
            pool_order = atoi(argv[optind]);    

            if (pool_order > MAX_POOL_ORDER) {
                printf("Max pool order is %d\n", MAX_POOL_ORDER);
                return -1;
            }

            offlined = hpmmap_offline_pool(pool_order, numa_zone);

            if (offlined == -1) {
                printf("Error offlining pool of order %d from zone %d\n",
                    pool_order, numa_zone);
            } else {
                printf("Offlined pool of order %d from zone %d\n",
                    pool_order, numa_zone);
            }
            break;
        }

        case MODE_ONLINE: {
            num_blocks = atoi(argv[optind]);
            onlined    = hpmmap_online_blocks(num_blocks, numa_zone);

            if (onlined == -1) {
                printf("Error onlinining %d blocks from zone %d\n",
                    num_blocks, numa_zone);
            } else {
                printf("Onlined %d blocks out of %d requested from zone %d\n",
                    onlined, num_blocks, numa_zone);
            }
            break;
        }

        case MODE_POOL_ONLINE: {
            pool_order = atoi(argv[optind]);

            if (pool_order > MAX_POOL_ORDER) {
                printf("Max pool order is %d\n", MAX_POOL_ORDER);
                return -1;
            }

            onlined = hpmmap_online_pool(pool_order, numa_zone);

            if (onlined == -1) {
                printf("Error onlinining pool of order %d from zone %d\n",
                    pool_order, numa_zone);
            } else {
                printf("Onlined pool of order %d from zone %d\n",
                    pool_order, numa_zone);
            }
            break;
        }

        default: {
            printf("Invalid mode specified: %d\n", mode);
        }
    }

    return 0; 
} 
