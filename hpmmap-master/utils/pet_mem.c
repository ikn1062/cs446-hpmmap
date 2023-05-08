/* 
 * PetLab memory utility functions
 * (c) Jack lange, 2013
 */


#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h> 
#include <sys/types.h> 
#include <unistd.h> 
#include <string.h>
#include <dirent.h> 

#include "pet_mem.h"
#include "../interface.h"

#define SYS_PATH   "/sys/devices/system/memory/"
#define NUMA_PATH  "/sys/devices/system/node/"
#define IOMEM_FILE "/proc/iomem"

#define BUF_SIZE 128

#ifdef DEBUG
#define dbg_printf printf
#else
#define dbg_printf 
#endif


struct ok_region {
    unsigned long start;
    unsigned long end;
    struct ok_region * next;
};

static struct ok_region * avail_regions = NULL;

struct block_bitmap {
    unsigned int starting_offset;
    unsigned int num_entries;
    unsigned char bitmap[0];
};



static int dir_filter(const struct dirent * dir) {
    if (strncmp("memory", dir->d_name, 6) == 0) {
        return 1;
    }

    return 0;
}


static int numa_filter(const struct dirent * dir) {
    if (strncmp("node", dir->d_name, 4) == 0) {
        return 1;
    }

    return 0;
}


static int dir_cmp(const struct dirent ** dir1, const struct dirent ** dir2) {
    int num1 = atoi((*dir1)->d_name + 6);
    int num2 = atoi((*dir2)->d_name + 6);

    return num1 - num2;
}

static int block_is_aligned(int index, unsigned long long alignment) {
    unsigned long long block_addr = index * pet_block_size();
    return (!(block_addr % alignment));
}


static void 
get_avail_regions() 
{
    FILE * mem_file = fopen(IOMEM_FILE, "r");
    struct ok_region * tmp_region = NULL;
    struct ok_region * new_region = NULL;
    char mem_buf[128];

    if (!mem_file) {
        printf("Error: Could not open iomem file\n");
        return;
    }

    memset(mem_buf, 0, 128);

    while (fgets(mem_buf, 128, mem_file)) {
        printf("mem_buf=%s\n",mem_buf);
        unsigned long start = 0;
        unsigned long end   = 0;
        char        * type  = NULL;

        int rc = sscanf(mem_buf, "%llx-%llx :", &start, &end);
        printf("rc=%d\n",rc);
        
        type  = index(mem_buf, ':');
        type += 2;

        if (strncmp(type, "System RAM", strlen("System RAM")) == 0) {
            new_region        = malloc(sizeof(struct ok_region));

            new_region->start = start;
            new_region->end   = end;
            new_region->next  = tmp_region;
            tmp_region        = new_region;
            printf("Adding region %llx-%llx\n", start, end);
        }
    }

    avail_regions = new_region;

    return;
}

static int block_is_avail(int index) {
    unsigned long long block_addr = index * pet_block_size();
    struct ok_region * iter       = NULL;


    if (avail_regions == NULL) {
        get_avail_regions();
    }

    iter = avail_regions;

    while (iter) {
        if ((iter->start <= block_addr) && 
	    (iter->end   >= (block_addr + pet_block_size() - 1))) {
            return 1;
        }

        iter = iter->next;
    }


    return 0;
}



const char * pet_mem_state_to_str(int mem_state) {
    if (mem_state == PET_BLOCK_RSVD) {
        return "RSVD";
    } else if (mem_state == PET_BLOCK_OFFLINE) {
        return "OFFLINE";
    } else if (mem_state == PET_BLOCK_ONLINE) {
        return "ONLINE";
    } 

    // else

    return "INVALID";
}


static struct block_bitmap *
get_block_bitmap(int numa_zone) 
{
    struct dirent ** namelist = NULL;
    struct block_bitmap * map = NULL;
    unsigned int num_entries  = 0;

    int size       = 0;
    int last_block = 0;
    int i          = 0;
    int j          = 0;
    char dir_path[512];

    memset(dir_path, 0, 512);

    if (numa_zone == -1) {
        snprintf(dir_path, 512, SYS_PATH);
    } else {
        snprintf(dir_path, 512, "%snode%d/", NUMA_PATH, numa_zone);
    }

    last_block = scandir(dir_path, &namelist, dir_filter, dir_cmp);

    dbg_printf("Scanned Directory %s\n", dir_path);
    //dbg_printf("last_block = %d\n", last_block);

    if (last_block == -1) {
        dbg_printf("Error scan directory (%s)\n", dir_path);
        return NULL;
    } else if (last_block == 0) {
        dbg_printf("Could not find any memory blocks at (%s)\n", dir_path);
        return NULL;
    }


    num_entries = atoi(namelist[last_block - 1]->d_name + 6) + 1;

    size = num_entries / 8;
    if (num_entries % 8) size++;

    dbg_printf("%d bitmap entries\n", size);

    map = malloc(sizeof(struct block_bitmap) + size);

    if (!map) {
        dbg_printf("ERROR: could not allocate space for bitmap\n");
        return NULL;
    }

    map->num_entries = num_entries;
    memset(map->bitmap, 0, size);


    for (i = 0; i < last_block - 1; i++) {
        struct dirent * tmp_dir = namelist[i];


        j = atoi(tmp_dir->d_name + 6);
        int major = j / 8;
        int minor = j % 8;


        //  dbg_printf("Checking block %d...", j);

        if (pet_is_block_removable(j) == 1) {
            //   dbg_printf("Removable\n");

            // check if block is already offline
            if (pet_block_status(j) == PET_BLOCK_ONLINE) {
                map->bitmap[major] |= (0x1 << minor);
            }
        } else {
            //  dbg_printf("Not removable\n");
        }
    }

    return map;
}


int pet_num_blocks(int numa_zone) {
    struct block_bitmap * bitmap = NULL;

    bitmap = get_block_bitmap(numa_zone);

    if (bitmap == NULL) {
        return -1;
    }

    return bitmap->num_entries;
}

int pet_block_to_numa_node(int index) {
    struct dirent ** namelist = NULL;
    int node_id = 0;
    char dir_path[512];

    memset(dir_path, 0, 512);

    snprintf(dir_path, 512, "%smemory%d/", SYS_PATH, index);

    node_id = scandir(dir_path, &namelist, numa_filter, dir_cmp);

    if (node_id != 1) {
        return -1;
    }

    node_id = atoi(namelist[0]->d_name + 4);

    return node_id;
}


int pet_mem_status(unsigned int * num_blocks, struct mem_block ** block_arr) {
    unsigned int       num_blks = pet_num_blocks(-1);
    struct mem_block * blks     = malloc(sizeof(struct mem_block) * num_blks);
    unsigned long      blk_size = pet_block_size();
    unsigned int i = 0;

    if (blks == NULL) {
        return -1;
    }

    for (i = 0; i < num_blks; i++) {
        blks[i].base_addr = (i * blk_size);
        blks[i].pages     = blk_size / 4096;
        blks[i].numa_node = pet_block_to_numa_node(i);
        blks[i].state     = pet_block_status(i);
    }


    *num_blocks = num_blks;
    *block_arr  = blks;

    return 0;

}


unsigned long long
pet_block_size() 
{
    unsigned long long block_size_bytes = 0;
    int  tmp_fd = 0;
    char tmp_buf[BUF_SIZE];

    tmp_fd = open(SYS_PATH "block_size_bytes", O_RDONLY);

    if (tmp_fd == -1) {
#ifdef DEBUG
        perror("Could not open block size file: " SYS_PATH "block_size_bytes");
#endif
        return -1;
    }

    if (read(tmp_fd, tmp_buf, BUF_SIZE) <= 0) {
#ifdef DEBUG
        perror("Could not read block size file: " SYS_PATH "block_size_bytes");
#endif
        return -1;
    }

    close(tmp_fd);
    block_size_bytes = strtoll(tmp_buf, NULL, 16);
    //   dbg_printf("Memory block size is %dMB (%d bytes)\n", block_size_bytes / (1024 * 1024), block_size_bytes);
    return block_size_bytes;
}






static int 
set_block_state(int    index, 
		char * state)
 {
    FILE * block_file = NULL;
    char fname[256];

    memset(fname, 0, 256);

    snprintf(fname, 256, "%smemory%d/state", SYS_PATH, index);

    block_file = fopen(fname, "r+");

    if (block_file == NULL) {
        //        dbg_printf("Could not open block file %d\n", index);
#ifdef DEBUG
        perror("\tError:");
#endif
        return -1;
    }

    dbg_printf("Setting block state for %d (%s) to %s\n", index, fname, state);

    fprintf(block_file, "%s\n", state);
    fclose(block_file);

    return 0;
}

int pet_online_block(int index) {
    if (pet_block_status(index) != PET_BLOCK_OFFLINE) {
        dbg_printf("Error: Block %d is already online\n", index);
        return -1;
    }

    if (set_block_state(index, "online") == -1) {
        dbg_printf("Error: Could not online block %d\n", index);
        return -1;
    }

    // Double check block was onlined, it might fail
    if (pet_block_status(index) != PET_BLOCK_ONLINE) {
        dbg_printf("Error: Failed to online block %d\n", index);
        return -1;
    }

    return 0;
}

int pet_offline_block(int index) {

    if (pet_is_block_removable(index) != 1) {
        dbg_printf("Error: Block %d not removable\n", index);
        return -1;
    }

    if (pet_block_status(index) != PET_BLOCK_ONLINE) {
        dbg_printf("Error: Block %d is already offline\n", index);
        return -1;
    }

    if (set_block_state(index, "offline") == -1) {
        dbg_printf("Error: Could not offline block %d\n", index);
        return -1;
    }

    // Double check block was offlined, it can sometimes fail
    if (pet_block_status(index) != PET_BLOCK_OFFLINE) {
        dbg_printf("Error: Failed to offline block %d\n", index);
        return -1;
    }

    return 0;
}

int pet_is_block_removable(int index) {
    int  block_fd = 0;       
    char status_str[BUF_SIZE];
    char fname[BUF_SIZE];

    // If the block is reserved for IO, then don't bother
    if (block_is_avail(index) == 0) {
        return 0;
    }

    memset(status_str, 0, BUF_SIZE);
    memset(fname,      0, BUF_SIZE);

    snprintf(fname, BUF_SIZE, "%smemory%d/removable", SYS_PATH, index);

    block_fd = open(fname, O_RDONLY);

    if (block_fd == -1) {
        dbg_printf("Could not open block removable file (%s)\n", fname);
        return -1;
    }

    if (read(block_fd, status_str, BUF_SIZE) <= 0) {
#ifdef DEBUG
        perror("Could not read block status");
#endif
        return -1;
    }

    close(block_fd);


    return atoi(status_str);
}



int pet_block_status(int index) {
    char fname[BUF_SIZE];
    char status_buf[BUF_SIZE];
    int block_fd = 0;


    memset(fname,      0, BUF_SIZE);
    memset(status_buf, 0, BUF_SIZE);

    snprintf(fname, BUF_SIZE, "%smemory%d/state", SYS_PATH, index);

    block_fd = open(fname, O_RDONLY);

    if (block_fd == -1) {
        dbg_printf("Could not open block file %d\n", index);
#ifdef DEBUG
        perror("\tError:");
#endif
        return PET_BLOCK_INVALID;
    }

    if (read(block_fd, status_buf, BUF_SIZE) <= 0) {
#ifdef DEBUG
        perror("Could not read block status");
#endif
        return PET_BLOCK_INVALID;
    }


    if (!pet_is_block_removable(index)) {
        return PET_BLOCK_RSVD;
    }

    //    dbg_printf("Checking offlined block %d (%s)...", index, fname);

    if (strncmp(status_buf, "offline", strlen("offline")) == 0) {
        return PET_BLOCK_OFFLINE;
    } else if (strncmp(status_buf, "online", strlen("online")) == 0) {
        return PET_BLOCK_ONLINE;
    } 

    // otherwise we have an error
    //    dbg_printf("ERROR\n");
    return PET_BLOCK_INVALID;
}





int 
pet_offline_blocks(int                num_blocks,
		   int                numa_zone, 
		   struct mem_block * block_arr)
 {
    unsigned int          cur_idx    = 0;
    struct block_bitmap * bitmap     = get_block_bitmap(numa_zone);
    unsigned long long    block_size = pet_block_size();
    unsigned long long i = 0;


    if (bitmap == NULL) {
        dbg_printf("Error getting block bitmap\n");
        return 0;
    }

    for (i = 0; i <= bitmap->num_entries; i++) {
        int major = i / 8;
        int minor = i % 8;

        if ((num_blocks > 0) && (cur_idx >= num_blocks)) break;

        if ((bitmap->bitmap[major] & (0x1 << minor)) != 0) {

            if (pet_offline_block(i) == -1) {
                dbg_printf("Error offlining block %d\n", i);
                continue;
            }

            block_arr[cur_idx].numa_node = numa_zone;
            block_arr[cur_idx].base_addr = (block_size * i);    // BASE_ADDR
            block_arr[cur_idx].pages     = (block_size / 4096); // NUM PAGES
            block_arr[cur_idx].state     = PET_BLOCK_OFFLINE;
            cur_idx++;
        }
    }

    free(bitmap);


    if ((num_blocks > 0) &&
	(cur_idx    < num_blocks)) {
        dbg_printf("Could only allocate %d (out of %d) blocks\n", 
		   cur_idx, num_blocks);
    }


    return cur_idx;

}


int pet_offline_node(int numa_node, struct mem_block * block_arr) {
    return pet_offline_blocks(-1, numa_node, block_arr);
}


int pet_online_blocks(int num_blocks, struct mem_block * block_arr) {
    unsigned long long block_size = pet_block_size();
    int i = 0;

    for (i = 0; i < num_blocks; i++) {
        unsigned int idx = (block_arr[i].base_addr / block_size);
        pet_online_block(idx);
    }

    return 0;
}


int 
pet_offline_contig_blocks(unsigned int         num_blocks, 
			  int                  numa_zone, 
			  unsigned long long   alignment, 
			  struct mem_block   * block_arr) 
{
    
    struct block_bitmap * bitmap       = get_block_bitmap(numa_zone);
    unsigned int          cur_idx      = 0;
    long long             region_start = -1;
    int i = 0;


    for (i = 0; i <= bitmap->num_entries; i++) {
        int major = i / 8;
        int minor = i % 8;


        if ((bitmap->bitmap[major] & (0x1 << minor)) != 0) {

            if (region_start == -1) {
                if (block_is_aligned(i, alignment)) {
                    region_start = i;
                }

            } else  if ((i - region_start) == num_blocks) {
                int j = 0;

                /* We found a contiguous region of num_blocks */
                /* Offline the blocks and return the region */

                for (j = 0; j < num_blocks; j++) {

                    if (pet_offline_block(region_start + j) == -1) {

                        //offline failed. Online everything we already did...

                        for (--j; j >= 0; j--) {
                            pet_online_block(region_start + j);
                        }

                        region_start = -1;

                        break;
                    }

                    block_arr[j].base_addr = (unsigned long long)(region_start + j) * pet_block_size();
                    block_arr[j].pages     = (num_blocks * pet_block_size()) / 4096;
                    block_arr[j].numa_node = numa_zone;
                    block_arr[j].state     = PET_BLOCK_OFFLINE;
                }

                if (region_start > -1) {
                    return 0;
                }
            }

        } else {
            region_start = -1;
        }
    }

    return -1;
}


int
pet_online_contig_blocks(int                num_blocks, 
			 unsigned long long base_addr) 
{
    int i = 0;
    unsigned int idx = base_addr / pet_block_size();

    for (i = 0; i < num_blocks; i++) {
        pet_offline_block(idx); 
    }

    return 0;
}
