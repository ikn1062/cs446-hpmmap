#include <linux/module.h>
#include <asm/unistd.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/preempt.h>
#include <linux/init.h>
#include <linux/syscalls.h>

MODULE_LICENSE("GPL");

# define PrintDebug(fmt, args...) printk("HPMMAP (debug): " fmt, ## args)

#define PrintError(fmt, args...) do {\
    printk("HPMMAP (error at %s:%d): %s: ", __FILE__, __LINE__, __func__);\
    printk(fmt, ## args);\
} while(0)

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_test;

int kallsyms_lookup_name_fn(const char *lookup_name, unsigned long *ret_address)
{
    struct kprobe kp = {
        .symbol_name = lookup_name
    };
    PrintDebug("Registering Kprobe");
    int check_reg = register_kprobe(&kp);
    if (check_reg < 0) {
        PrintError("failed to register kprobe for %s, returned %d\n", lookup_name, check_reg);
        return check_reg;
    }
    *ret_address = (unsigned long) kp.addr;

    kallsyms_lookup_name_test = (kallsyms_lookup_name_t) kp.addr;

    PrintDebug("Unregistering Kprobe");
    unregister_kprobe(&kp);

    return 0;
}

int __init test_init(void) 
{
    int err = 0;
    unsigned long add;
    PrintDebug("Registering Krpobe for %s", "kallsyms_lookup_name");
    err = kallsyms_lookup_name_fn("kallsyms_lookup_name", &add);

    PrintDebug("Testing Kallsyms lookup name func");
    unsigned long current_kprobe = kallsyms_lookup_name_test("current_kprobe");
    PrintDebug("Got Kprobe address: 0x%p", current_kprobe);
    PrintDebug("Got Kprobe address: 0x%lx", current_kprobe);
    PrintDebug("Complete");
    
    return 0;
}

static void __exit
test_exit(void ) 
{

}

module_init(test_init);
module_exit(test_exit);
