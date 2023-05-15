#include <asm/unistd.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/preempt.h>
#include <linux/version.h>
//#include <linux/kthread.h>

#include "hpmmap.h"
#include "probe.h"
#include "mmap.h"

/* copy_process uses a kretprobe because we need to let the clone happen first */
static struct kretprobe copy_process_probe;

/* 
UPDATE NEWEST: Removed and replaced by Ftrace call 

UPDATE: do_exit originally used a jprobe to avoid interrupt context, kprobe should have this automatically disabled
*/
// static struct kprobe    do_exit_probe;

/* get_user_pages functions use kprobes - we won't sleep in them */
static struct kprobe    get_user_pages_probe;
static struct kprobe    __get_user_pages_probe;
static struct kprobe    get_user_pages_fast_probe;
static struct kprobe    __get_user_pages_fast_probe;


//#if LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)
unsigned long kallsyms_lookup_name_fn(const char *lookup_name, unsigned long ret_address)
{
    struct kprobe kp = {
        .symbol_name = lookup_name
    };

    int check_reg = register_kprobe(&kp);
    if (check_reg < 0) {
        PrintError("failed to register kprobe for %s, returned %d\n", lookup_name, check_reg);
        return check_reg;
    }
    ret_address = (unsigned long) kp.addr;
    unregister_kprobe(&kp);
}
/*
#else 
unsigned long kallsyms_lookup_name_fn(const char *lookup_name)
{
    return kallsyms_lookup_name(lookup_name);
}
#endif
*/


/* copy_process_probe private data */
struct hpmmap_probe_data {
    unsigned long clone_flags;
};

// do our own resets to avoid access of kernel symbol current_kprobe
static void
hpmmap_reset_current_kprobe(void)
{
    extern void *__hpmmap_current_kprobe;
    
    __this_cpu_write(__hpmmap_current_kprobe, NULL);
}


//#define PREEMPT_ON()  preempt_enable_no_resched()
#define PREEMPT_ON()  //  barrier()  // presumably needed even on nopreempt kernel...
#define RESET_CURRENT_KPROBE() hpmmap_reset_current_kprobe(); PREEMPT_ON();
 
//#define RESET_CURRENT_KPROBE() reset_current_kprobe()



/* 
 * On x86, the clone_flags parameter is stored in rdi. So, save rdi in the kretprobe
 * instance
 */
static int
hpmmap_copy_process_enter(struct kretprobe_instance * ri,
                          struct pt_regs            * regs)
{
    struct hpmmap_probe_data * data = (struct hpmmap_probe_data *)ri->data;

    data->clone_flags = regs->di;
    return 0;
}

static int
hpmmap_copy_process_exit(struct kretprobe_instance * ri,
                         struct pt_regs            * regs)
{
    struct hpmmap_probe_data * data = (struct hpmmap_probe_data *)ri->data;
    struct task_struct       * task = (struct task_struct *)regs_return_value(regs);

    /* Check copy_process return value */
    if (IS_ERR(task)) {
        return 0;
    }

    /* We don't need to do anything unless the VM is being shared */
    if (!(data->clone_flags & CLONE_VM)) {
        return 0;
    }

    /* Setup the HPMMAP VM for the new task */
    register_process_clone(current->pid, task->pid);
    return 0;
}

/* Removed and replaced by Ftrace call */
/*
static int
hpmmap_do_exit(struct kprobe  * kp,
               struct pt_regs * regs)
{
    //local_irq_disable();
    unmap_process(current->pid);
    //local_irq_enable();
    return 0;
}
*/


static long
hpmmap_get_user_pages_fn(struct task_struct     * tsk, 
                         struct mm_struct       * mm, 
                         unsigned long            start, 
                         unsigned long            nr_pages, 
                         int                      write,
                         int                      force, 
                         struct page           ** pages, 
                         struct vm_area_struct ** vmas)
{
    return hpmmap_get_user_pages(tsk->pid, start, nr_pages, pages, vmas, 1);
}

static long
__hpmmap_get_user_pages_fn(struct task_struct     * tsk,
                           struct mm_struct       * mm,
                           unsigned long            start,
                           unsigned long            nr_pages,
                           unsigned int             foll_flags,
                           struct page           ** pages,
                           struct vm_area_struct ** vmas,
                           int                    * nonblocking)
{
    /* We obviously don't need to go to disk for pages */
    if (nonblocking) {
        *nonblocking = 1;
    }

    return hpmmap_get_user_pages(tsk->pid, start, nr_pages, pages, vmas, 1);
}

static long
hpmmap_get_user_pages_fast_fn(unsigned long    start,
                              int              nr_pages,
                              int              write,
                              struct page   ** pages)
{
    return hpmmap_get_user_pages(current->pid, start, nr_pages, pages, NULL, 0);
}

static long
__hpmmap_get_user_pages_fast_fn(unsigned long    start,
                                int              nr_pages,
                                int              write,
                                struct page   ** pages)
{
    return hpmmap_get_user_pages(current->pid, start, nr_pages, pages, NULL, 0);
}


static int
hpmmap_get_user_pages_probe(struct kprobe  * kp,
                            struct pt_regs * regs)
{
    struct task_struct * tsk      = (struct task_struct *)regs->di;
    unsigned long        start    = (unsigned long)regs->dx;
    unsigned long        nr_pages = (unsigned long)regs->cx;
    int                  ret      = 0;

    if (!tsk) {
        return 0;
    }

    ret = hpmmap_check_user_pages(tsk->pid, start, nr_pages);

    if (ret == 0) {
        /* We found the region - blow away the original function call */
        regs->ip = (unsigned long)&hpmmap_get_user_pages_fn;

        RESET_CURRENT_KPROBE();

        return 1;
    }

    return 0;
}

static int
__hpmmap_get_user_pages_probe(struct kprobe  * kp,
                              struct pt_regs * regs)
{
    struct task_struct * tsk      = (struct task_struct *)regs->di;
    unsigned long        start    = (unsigned long)regs->dx;
    unsigned long        nr_pages = (unsigned long)regs->cx;
    int                  ret      = 0;

    if (!tsk) {
        return 0;
    }

    ret = hpmmap_check_user_pages(tsk->pid, start, nr_pages);

    if (ret == 0) {
        /* We found the region - blow away the original function call */
        regs->ip = (unsigned long)&__hpmmap_get_user_pages_fn;

        RESET_CURRENT_KPROBE();

        return 1;
    }

    return 0;
}

static int
hpmmap_get_user_pages_fast_probe(struct kprobe  * kp,
                                 struct pt_regs * regs)
{
    unsigned long start    = (unsigned long)regs->di;
    unsigned long nr_pages = (unsigned long)regs->si;
    int           ret      = 0;

    ret = hpmmap_check_user_pages(current->pid, start, nr_pages);

    if (ret == 0) {
        /* We found the region - blow away the original function call */
        regs->ip = (unsigned long)&hpmmap_get_user_pages_fast_fn;

        RESET_CURRENT_KPROBE();

        return 1;
    }

    return 0;
}

static int
__hpmmap_get_user_pages_fast_probe(struct kprobe  * kp,
                                   struct pt_regs * regs)
{
    unsigned long start    = (unsigned long)regs->di;
    unsigned long nr_pages = (unsigned long)regs->si;
    int           ret      = 0;

    ret = hpmmap_check_user_pages(current->pid, start, nr_pages);

    if (ret == 0) {
        /* We found the region - blow away the original function call */
        regs->ip = (unsigned long)&__hpmmap_get_user_pages_fast_fn;

        RESET_CURRENT_KPROBE();

        return 1;
    }

    return 0;
}

int check_sym;
int 
init_hpmmap_probes(void) 
{
    unsigned long symbol_addr = 0;

    /* copy_process */
    {
        check_sym = kallsyms_lookup_name_fn("copy_process", &symbol_addr);
        if (check_sym < 0) {
            return -1;
        }

        if (symbol_addr == 0) {
            check_sym = kallsyms_lookup_name_fn("copy_process.part.25", &symbol_addr);

            if (symbol_addr == 0 || check_sym < -1) {
                PrintError("Could not find copy_process symbol address\n");
                return -1;
            }
        }

        /* Register kretprobe */
        memset(&copy_process_probe, 0, sizeof(struct kretprobe));

        copy_process_probe.kp.addr       = (kprobe_opcode_t *)symbol_addr;
        copy_process_probe.entry_handler = hpmmap_copy_process_enter;
        copy_process_probe.handler       = hpmmap_copy_process_exit;
        copy_process_probe.maxactive     = NR_CPUS;
        copy_process_probe.data_size     = sizeof(struct hpmmap_probe_data);

        register_kretprobe(&copy_process_probe);
    }

    /* Removed and replaced by Ftrace call */
    /* do_exit */
    /*
    {
        memset(&do_exit_probe, 0, sizeof(struct kprobe));

        do_exit_probe.symbol_name = "do_exit";
        do_exit_probe.pre_handler = hpmmap_do_exit;

        register_kprobe(&do_exit_probe);
    }
    */

    /* get_user_pages */
    {
        memset(&get_user_pages_probe, 0, sizeof(struct kprobe));

        get_user_pages_probe.symbol_name = "get_user_pages";
        get_user_pages_probe.pre_handler = hpmmap_get_user_pages_probe;

        register_kprobe(&get_user_pages_probe);
    }

    /* __get_user_pages */
    {
        memset(&__get_user_pages_probe, 0, sizeof(struct kprobe));

        __get_user_pages_probe.symbol_name = "__get_user_pages";
        __get_user_pages_probe.pre_handler = __hpmmap_get_user_pages_probe;

        register_kprobe(&__get_user_pages_probe);
    }

    /* get_user_pages_fast */
    {
        memset(&get_user_pages_fast_probe, 0, sizeof(struct kprobe));

        get_user_pages_fast_probe.symbol_name = "get_user_pages_fast";
        get_user_pages_fast_probe.pre_handler = hpmmap_get_user_pages_fast_probe;

        register_kprobe(&get_user_pages_fast_probe);
    }

    /* __get_user_pages_fast */
    {
        memset(&__get_user_pages_fast_probe, 0, sizeof(struct kprobe));

        __get_user_pages_fast_probe.symbol_name = "__get_user_pages_fast";
        __get_user_pages_fast_probe.pre_handler = __hpmmap_get_user_pages_fast_probe;

        register_kprobe(&__get_user_pages_fast_probe);
    }

    PrintDebug("HPMMAP probes initialized\n");

    return 0;
}

int 
deinit_hpmmap_probes(void) 
{
    unregister_kretprobe(&copy_process_probe);
    
    /* Removed and replaced by Ftrace call */
    // unregister_kprobe(&do_exit_probe);

    unregister_kprobe(&get_user_pages_probe);
    unregister_kprobe(&__get_user_pages_probe);
    unregister_kprobe(&get_user_pages_fast_probe);
    unregister_kprobe(&__get_user_pages_fast_probe);

    PrintDebug("HPMMAP probes deinitialized\n");
    return 0;
}



#if 0
static void
hpmmap_reset_current_kprobe(void)
{
    unsigned long symbol_addr = 0;
    struct kprobe * current_kprobe = NULL;

    /* current_kprobe */
    {
        symbol_addr = kallsyms_lookup_name_fn("current_kprobe");

        if (symbol_addr == 0) {
            PrintError("Could not find current_kprobe symbol address\n");
            return;
        }

        current_kprobe = (struct kprobe *)symbol_addr;
    }

    __this_cpu_write(current_kprobe, NULL);
}
#endif
