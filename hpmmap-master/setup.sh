#! /bin/sh

# load module
mod/reload.sh
dmesg -c &> /dev/null

# check mem status
utils/mem_ctrl -s

# allocate some memory to hpmmap
utils/mem_ctrl -a 4 -n 0

# set enviroment variable 
export OMPI_COMM_WORLD_LOCAL_RANK=0
