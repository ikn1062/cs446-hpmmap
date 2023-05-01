/* 
 * PetLab memory utility functions
 * (c) Jack lange, 2013
 */

#ifndef __PET_MEM_H__
#define __PET_MEM_H__

#define PET_BLOCK_RSVD     2
#define PET_BLOCK_ONLINE   1
#define PET_BLOCK_OFFLINE  0
#define PET_BLOCK_INVALID -1

struct mem_block {
    int numa_node;
    unsigned long long base_addr;
    unsigned long long pages;
    int state;
};


/* High level interfaces */

unsigned long long pet_block_size();
int pet_num_blocks(int numa_zone);
int pet_mem_status(unsigned int * num_blocks, struct mem_block ** block_arr);

// 2nd argument is an array of blocks with num_blocks entries
int pet_offline_blocks(int num_blocks, int numa_zone, 
		       struct mem_block * block_arr);

int pet_offline_node(int numa_node, struct mem_block * block_arr);

int pet_online_blocks(int num_blocks, struct mem_block * block_arr);

int pet_offline_contig_blocks(unsigned int num_blocks, int numa_zone, 
			      unsigned long long alignment, 
			      struct mem_block * block_arr);

int pet_online_contig_blocks(int num_blocks, unsigned long long base_addr);

const char * pet_mem_state_to_str(int mem_state);



/* Lower level interfaces */
int pet_block_to_numa_node(int index);
int pet_offline_block(int index);
int pet_online_block(int index);
int pet_block_status(int index);
int pet_is_block_removable(int index);






#endif
