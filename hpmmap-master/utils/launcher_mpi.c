#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <asm/unistd.h>

#include <numa.h>

#include "../interface.h"

#define DEFAULT_PIN -1

int main(int argc, char ** argv) {
    char * pin_str   = NULL;
    char * cmd       = NULL;
    pid_t  pid       = 0;
    int    fd        = 0;
    int    pin       = 0;
    int    status    = 0;

    pid = fork();

    switch (pid) {
        case -1:
            perror("Failed to fork");
            return -1;

        case 0: 
            fd = open("/dev/" DEV_FILENAME, O_RDONLY);

            if (fd == -1) {
                fprintf(stderr, "Error opening HPMMAP device file (%s)\n",
                    DEV_FILENAME);
                return -1;
            }

            /* HPMMAP pin options:
             * -1: interleave
             *  *: pin to specific node
             */

            pin_str = getenv("HPMMAP_PIN");
            if (pin_str == NULL) {
                pin = DEFAULT_PIN;
            } else {
                pin = atoi(pin_str);
            }

            switch (pin) {
                case -1: {
                    /* We interleave between all numa zones based on ompi local rank
                     * IDs */
                    struct bitmask * mask      = NULL;
                    char           * ompi_str  = NULL;
                    int              rank      = 0;
                    int              num_nodes = 0;
                    int              num_cpus  = 0;
                    int              node      = 0;
                    int              node_off  = 0;
                    int              i         = 0;
                    cpu_set_t        cpus;

                    ompi_str = getenv("OMPI_COMM_WORLD_LOCAL_RANK");

                    if (ompi_str == NULL) {
                        fprintf(stderr, "OMPI_COMM_WORLD_LOCAL_RANK not found in environment. Exiting launcher...\n");
                        return -1;
                    }

                    rank      = atoi(ompi_str);
                    num_nodes = numa_num_task_nodes();
                    node      = rank % num_nodes;
                    node_off  = rank / num_nodes;

                    if (node == 0 && node_off == 0) {
                        fprintf(stderr, "Launcher: Pin mode interleave\n");
                    }

                    /* Allocate numa bitmask */
                    mask = numa_allocate_cpumask();

                    /* Set the bitmask based on numa node */
                    status = numa_node_to_cpus(node, mask);
                    if (status != 0) {
                        perror("numa_node_to_cpus()");
                        return status;
                    }
                    
                    /* Convert to cpu mask */
                    CPU_ZERO(&cpus);
                    num_cpus = 0;

                    /* Grab the "node_off'th" cpu */
                    for (i = 0; i < numa_num_task_cpus(); i++) {
                        if (numa_bitmask_isbitset(mask, i)) {
                            if (num_cpus++ == node_off) {
                                CPU_SET(i, &cpus);
                                break;
                            }
                        }
                    }

                    numa_free_nodemask(mask);

                    /* Pin to CPU */
                    status = sched_setaffinity(0, sizeof(cpu_set_t), &cpus);
                    if (status != 0) {
                        perror("sched_setaffinity()");
                        return status;
                    }

                    break;
                }

                default: {
                    /* Pin to given numa node */
                    struct bitmask * mask      = NULL;
                    char           * ompi_str  = NULL;
                    int              rank      = 0;
                    int              num_nodes = 0;
                    int              num_cpus  = 0;
                    int              node_off  = 0;
                    int              i         = 0;
                    cpu_set_t        cpus;

                    if (pin < 0) {
                        fprintf(stderr, "Invalid HPMMAP PIN option: %d\n", pin);
                        return -1;
                    }

                    ompi_str  = getenv("OMPI_COMM_WORLD_LOCAL_RANK");
                    num_nodes = numa_num_task_nodes();

                    if (pin >= num_nodes) {
                        fprintf(stderr, "Cannot pin to numa node %d: only %d nodes present\n",
                            pin, num_nodes);
                        return -1;
                    }


                    if (ompi_str == NULL) {
                        fprintf(stderr, "OMPI_COMM_WORLD_LOCAL_RANK not found in environment. Pinning to whole numa node\n");
                        node_off = -1;
                    } else {
                        rank     = atoi(ompi_str);
                        node_off = rank;
                    }

                    if (node_off == 0) {
                        fprintf(stderr, "Launcher: Pin node %d\n", pin);
                    }

                    /* Allocate numa bitmask */
                    mask = numa_allocate_cpumask();

                    /* Set the bitmask based on numa node */
                    status = numa_node_to_cpus(pin, mask);
                    if (status != 0) {
                        perror("numa_node_to_cpus()");
                        return status;
                    }
                    
                    /* Convert to cpu mask */
                    CPU_ZERO(&cpus);
                    num_cpus = 0;

                    if (node_off == -1) {
                        /* Grab all cpus from numa node */
                        for (i = 0; i < numa_num_task_cpus(); i++) {
                            if (numa_bitmask_isbitset(mask, i)) {
                                CPU_SET(i, &cpus);
                            }
                        }
                    } else {
                        /* Grab the "node_off'th" cpu */
                        for (i = 0; i < numa_num_task_cpus(); i++) {
                            if (numa_bitmask_isbitset(mask, i)) {
                                if (num_cpus++ == node_off) {
                                    CPU_SET(i, &cpus);
                                    break;
                                }
                            }
                        }
                    }

                    numa_free_nodemask(mask);

                    /* Pin  */
                    status = sched_setaffinity(0, sizeof(cpu_set_t), &cpus);
                    if (status != 0) {
                        perror("sched_setaffinity()");
                        return status;
                    }

                    break;
                }
            }

            // Register process
            ioctl(fd, REGISTER_PID, getpid());
            close(fd);

            // Exec command
            execvp(*(++argv), argv);

            perror("Failed to exec");
            return -1;

        default:
            wait(NULL);
            break;
    }

    return 0;
}
