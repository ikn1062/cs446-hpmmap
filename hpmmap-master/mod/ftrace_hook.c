#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kprobes.h>

#include "ftrace_hook.h"
#include "hpmmap.h"
#include "probe.h"
#include "mmap.h"

static struct ftrace_hook do_exit_fhook;
static int err;
extern kallsyms_lookup_name_t kallsyms_lookup_name_fn;

// can change this to call the original do_exit while being protected in interrupt context switch
static void notrace do_exit_function(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *op, struct pt_regs *regs)
{
    // change to save these states
    //local_irq_save();
    unmap_process(current->pid);
    //local_irq_restore();
}


static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
    hook->address = kallsyms_lookup_name_fn(hook->name);
    if (hook->address == 0) {
        return ENOENT;
    }

    if (!hook->address) {
        PrintError("unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

    // *((unsigned long*) hook->original) = hook->address;

    return 0;
}

static int fh_install_hook(struct ftrace_hook *hook)
{
    int err;

    err = fh_resolve_hook_address(hook);
    if (err) {
        return err;
    }

    hook->ops.func = hook->function;
    hook->ops.flags = FTRACE_OPS_FL_RECURSION;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        PrintError("ftrace_set_filter_ip failed %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        PrintError("register_ftrace_function failed %d\n", err);
        return err;
    }

    return 0;
}

static void fh_remove_hook(struct ftrace_hook *hook)
{
    int err;

    err = unregister_ftrace_function(&hook->ops);
    if (err) {
        PrintError("unregister_ftrace_function failed %d\n", err);
    }

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err) {
        PrintError("ftrace_set_filter_ip failed %d\n", err);
    }
}


int init_hpmmap_ftrace(void)
{   
    memset(&do_exit_fhook, 0, sizeof(struct ftrace_hook));

    do_exit_fhook.name = "do_exit";
    do_exit_fhook.function = do_exit_function;

    err = fh_install_hook(&do_exit_fhook);
    if (err) {
        PrintError("fh_install_hook failed %d\n", err);
        return -1;
    }

    PrintDebug("HPMMAP ftrace initialized\n");
    return 0;
}

int deinit_hpmmap_ftrace(void)
{
    fh_remove_hook(&do_exit_fhook);
    PrintDebug("HPMMAP ftrace deinitialized\n");
    return 0;
}








