/*
 * Wrappers for hooking system calls
 *
 * (c) Brian Kocoloski <briankoco@cs.pitt.edu>, 2013
 *
 */

#ifndef _OVERRIDE_H
#define _OVERRIDE_H

#include <linux/types.h>

void *
hook_syscall(void * new_fn, 
             u32 index);

int
unhook_syscall(void * orig_fn, 
               u32 index);


#endif /* _OVERRIDE_H */
