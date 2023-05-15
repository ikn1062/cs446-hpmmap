#include <asm/unistd.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/preempt.h>


int kallsyms_lookup_name_fn(const char *lookup_name, unsigned long *ret_address)
{
    struct kprobe kp = {
        .symbol_name = lookup_name
    };

    int check_reg = register_kprobe(&kp);
    if (check_reg < 0) {
        PrintError("failed to register kprobe for %s, returned %d\n", lookup_name, check_reg);
        return check_reg;
    }
    *ret_address = (unsigned long) kp.addr;
    unregister_kprobe(&kp);

    return 0;
}

int main()
{
    int err = 0;
    unsigned long add;

    err = kallsyms_lookup_name_fn("current_kprobe", &add);
    
    return 0;
}