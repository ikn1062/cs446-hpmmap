#!/bin/sh

../utils/mem_ctrl -r 80 -n 0
../utils/mem_ctrl -r 80 -n 1
./reload_mod.sh
dmesg -c &> /dev/null
../utils/mem_ctrl -a 80 -n 0
../utils/mem_ctrl -a 80 -n 1
