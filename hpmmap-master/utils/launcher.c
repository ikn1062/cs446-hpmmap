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
