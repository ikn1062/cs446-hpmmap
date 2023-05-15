#ifndef _HPMMAP_FTRACE_H
#define _HPMMAP_FTRACE_H

struct ftrace_hook 
{
    const char *name;
    void *function;
    // void *original;

    unsigned long address;
    struct ftrace_ops ops;
};


int init_hpmmap_ftrace(void);
int deinit_hpmmap_ftrace(void);


#endif /* _HPMMAP_FTRACE_H */