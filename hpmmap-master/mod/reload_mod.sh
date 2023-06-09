#!/bin/sh


echo 0 > /proc/sys/debug/kprobes-optimization

# Remove module
if [ $(lsmod | grep hpmmap | wc -l) -eq 1 ]; then
    rmmod hpmmap
fi

# Load module - lookup addr of syscall table
insmod hpmmap.ko syscall_table_addr=0x$(grep -i "r sys_call_table" /proc/kallsyms | sed 's/\([0-9a-f]*\) [rR] sys_call_table/\1/') cur_kprobe=0x$(grep current_kprobe /proc/kallsyms | cut -d " " -f 1 -z)

# Optionally, set hpmmap permissions to avoid running applications as root
sleep 2
chgrp ishaann /dev/hpmmap 
chmod 666 /dev/hpmmap
