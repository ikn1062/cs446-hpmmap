#include <linux/module.h>
#include <linux/moduleparam.h>

#include "override.h"
#include "util-hashtable.h"
#include "probe.h"


// Module parameter
static const char *sys_call_table_name = "sys_call_table";
static unsigned long syscall_table_addr = 0;
// static unsigned long syscall_table_addr = 0;
// module_param(syscall_table_addr, ulong, 0);
// MODULE_PARM_DESC(syscall_table_addr, "Address of system call table");
// End module parameter

static void
enable_page_protection( void )
{ 
    unsigned long value = 0;

    asm volatile("mov %%cr0, %0" : "=r" (value));

    if (value & 0x00010000) {
        return;
    }

    asm volatile("mov %0, %%cr0" : : "r" (value | 0x00010000));
}

static void 
disable_page_protection( void )
{ 
    unsigned long value = 0;

    asm volatile("mov %%cr0, %0" : "=r" (value));

    if ((value & 0x00010000) == 0) {
        return;
    }

    asm volatile("mov %0, %%cr0" : : "r" (value & ~0x00010000));
}

// Returns original system call
int check_err;
void * 
hook_syscall(void * new_fn, 
             u32    index) 
{
    unsigned long ** syscall_table = NULL;
    void *           orig_fn       = NULL;

    syscall_table_addr = kallsyms_lookup_name_fn(sys_call_table_name);
    if (syscall_table_addr == 0) {
        // Userspace couldn't find syscall table - we will have to search for it here ...
        return NULL;
    }

    syscall_table = (unsigned long **)syscall_table_addr;

    disable_page_protection();
    {
        orig_fn              = (void *)syscall_table[index];
        syscall_table[index] = new_fn;
    }
    enable_page_protection();

    return orig_fn;
}

int
unhook_syscall(void * orig_fn, 
               u32    index)
{
    unsigned long ** syscall_table = NULL;

    if (syscall_table_addr == 0) {
        return 0;
    }

    syscall_table = (unsigned long **)syscall_table_addr;

    disable_page_protection();
    {
        syscall_table[index] = orig_fn;
    }
    enable_page_protection();

    return 0;
}
