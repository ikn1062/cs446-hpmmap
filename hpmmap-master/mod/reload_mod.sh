#!/bin/sh


echo 0 > /proc/sys/debug/kprobes-optimization

# Remove module
if [ $(lsmod | grep hpmmap | wc -l) -eq 1 ]; then
    rmmod hpmmap
fi

# Load module - lookup addr of syscall table
insmod hpmmap.ko cur_kprobe=0x$(grep current_kprobe /proc/kallsyms | cut -d " " -f 1 -z)

# Optionally, set hpmmap permissions to avoid running applications as root
sleep 2
chgrp ishaan-vm-2204 /dev/hpmmap 
chmod 666 /dev/hpmmap
