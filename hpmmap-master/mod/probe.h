/*
 * Handle various processing by probing some kernel functions
 *
 * Cloning: probe 'copy_process' to setup HPMMAPs for cloned threads/processes
 * Exiting: probe 'do_exit' to cleanup HPMMAPs for dying threads/processes
 *
 * Page table walking: probe 'get_user_pages' to prevent page table walks over HPMMAP
 * regions
 *
 * (c) Brian Kocoloski <briankoco@cs.pitt.edu>, 2014
 *
 */

#ifndef _PROBE_H
#define _PROBE_H

int init_hpmmap_probes(void);
int deinit_hpmmap_probes(void);

#endif /* _PROBE_H */
