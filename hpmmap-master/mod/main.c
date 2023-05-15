#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/version.h>

#include <asm/types.h>
#include <asm/syscalls.h>

#include "../interface.h"
#include "hpmmap.h"
#include "buddy.h"
#include "pgtables.h"
#include "mmap.h"
#include "probe.h"
#include "mm.h"
#include "hpmmap_syms.h"
#include "ftrace_hook.h"

MODULE_LICENSE("GPL");

static struct cdev    ctrl_dev;
struct class        * hpmmap_class = NULL;
static int            major_num    = 0;

static struct proc_dir_entry  * hpmmap_proc_dir = NULL;
static struct buddy_memzone  ** memzones        = NULL;

// spinlock_t node_lock;

uintptr_t 
hpmmap_alloc_pages_on_node(u64 num_pages, 
                           int node_id) 
{
    if (node_id == -1) {
        int cpu_id = get_cpu();
        put_cpu();

        node_id = numa_cpu_to_node(cpu_id);
    } else if (numa_num_nodes() == 1) {
        // Ignore the NUMA zone here
        node_id = 0;
    } else if (node_id >= numa_num_nodes()) {
        // We are a NUMA aware, and requested an invalid node
        PrintError("Requesting memory from an invalid NUMA node. (Node: %d) (%d nodes on system)\n",
           node_id, numa_num_nodes());
        return 0;
    }

    {
        uintptr_t ret = buddy_alloc(memzones[node_id], get_order(num_pages * PAGE_SIZE) + PAGE_SHIFT);

        if (ret > 0) {
            u64 i = 0;

            for (i = 0; i < num_pages; i++) {
                uintptr_t     addr = (ret + (i * PAGE_SIZE));
                struct page * page = pfn_to_page(addr >> PAGE_SHIFT);

                get_page(page);
            }
        }

        return ret;
    }
}

uintptr_t hpmmap_alloc_pages(u64 num_pages) {
    return hpmmap_alloc_pages_on_node(num_pages, -1);
}

unsigned long long 
hpmmap_check_pages(int node_id)
{
    if (node_id == -1) {
        int cpu_id = get_cpu();
        put_cpu();

        node_id = numa_cpu_to_node(cpu_id);
    } else if (numa_num_nodes() == 1) {
        // Ignore the NUMA zone here
        node_id = 0;
    } else if (node_id >= numa_num_nodes()) {
        // We are a NUMA aware, and requested an invalid node
        PrintError("Requesting memory from an invalid NUMA node. (Node: %d) (%d nodes on system)\n",
           node_id, numa_num_nodes());
        return 0;
    }

    return (buddy_check(memzones[node_id]) / PAGE_SIZE_4KB);
}


void 
hpmmap_free_pages(uintptr_t page_addr, 
                  u64       num_pages) 
{
    int node_id = numa_addr_to_node(page_addr);

    buddy_free(memzones[node_id], page_addr, get_order(num_pages * PAGE_SIZE) + PAGE_SHIFT);

    {
        u64 i = 0;

        for (i = 0; i < num_pages; i++) {
            uintptr_t     addr = (page_addr + (i * PAGE_SIZE));
            struct page * page = pfn_to_page(addr >> PAGE_SHIFT);

            put_page(page);
        }
    }
}

static int 
hpmmap_free_memory(int         node_id, 
                   u64         num_pages, 
                   uintptr_t * base_addr) 
{
    struct buddy_memzone * zone = memzones[node_id];

    if (!zone) {
        return -1;
    }

    return buddy_remove_memory(zone, num_pages * PAGE_SIZE, (unsigned long *)base_addr);
}


static long 
hpmmap_ioctl(struct file  * filp, 
             unsigned int   ioctl, 
             unsigned long  arg) 
{
    void __user * argp = (void __user *)arg;
    
    switch (ioctl) {
        case ADD_MEMORY: {
            struct memory_range reg;
            uintptr_t base_addr = 0;        
            u32 num_pages       = 0;
            int node_id         = 0;
            int pool_order      = 0;

            if (copy_from_user(&reg, argp, sizeof(struct memory_range))) {
                PrintError("Cannot copy memory region from userspace\n");
                return -EFAULT;
            }

            base_addr = (uintptr_t)reg.base_addr;
            num_pages = reg.pages;

            node_id = numa_addr_to_node(base_addr);
            if (node_id != reg.node_id) {
                PrintError("Malformed memory registration struct\n");
                return -EFAULT;
            }
              
            PrintDebug("Managing %dMB of memory starting at %p (%lluMB)\n", 
                   (unsigned int)(num_pages * PAGE_SIZE) / (1024 * 1024), 
                   (void *)base_addr, 
                   (unsigned long long)(base_addr / (1024 * 1024)));
          
          
            //   pool_order = fls(num_pages); 
            pool_order = get_order(num_pages * PAGE_SIZE) + PAGE_SHIFT;
            buddy_add_pool(memzones[node_id], base_addr, pool_order);

            {
                u32 i = 0;

                for (i = 0; i < num_pages; i++) {
                    uintptr_t     addr = (base_addr + (i * PAGE_SIZE));
                    struct page * page = pfn_to_page(addr >> PAGE_SHIFT);

                    init_page_count(page);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
                    reset_page_mapcount(page);
#else
                    page_mapcount_reset(page);
#endif
                    SetPageReserved(page);
                }
            }

            break;
        }

        case RELEASE_MEMORY: {
            struct memory_range reg;
            uintptr_t base_addr = 0;        
            u32 num_pages       = 0;
            int node_id         = 0;

            if (copy_from_user(&reg, argp, sizeof(struct memory_range))) {
                PrintError("Cannot copy memory region from userspace\n");
                return -EFAULT;
            }

            num_pages = reg.pages;
            node_id   = reg.node_id;

            if (hpmmap_free_memory(node_id, num_pages, &base_addr)) {
                reg.base_addr = 0;
                reg.pages     = 0;
            } else {
                PrintDebug("Releasing %dMB of memory starting at %p (%lluMB)\n", 
                       (unsigned int)(num_pages * PAGE_SIZE) / (1024 * 1024), 
                       (void *)base_addr, 
                       (unsigned long long)(base_addr / (1024 * 1024)));

                reg.base_addr = base_addr;
            }

            if (copy_to_user(argp, &reg, sizeof(struct memory_range))) {
                PrintError("Cannot copy memory region to userspace\n");
                return -EFAULT;
            }

            break;
        }

        case REGISTER_PID: {
            // User process wants hpmmap management
            u32 pid = (u32)arg;

            if (register_process(pid) == -1) {
                return -EFAULT;
            }

            break;
        }

        case DEREGISTER_PID: {
            u32 pid = (u32)arg;

            if (unmap_process(pid) == -1) {
                return -EFAULT;
            }

            break;
        }

        default:
            PrintError("Unhandled ioctl (%d)\n", ioctl);
            break;
    }

    return 0;

}


static int hpmmap_open(struct inode * inode, 
                       struct file * filp)
{
    return 0;
}


static int hpmmap_release(struct inode * inode, 
                          struct file * filp)
{
    /*
    // Free memory allocated by this process
    unmap_process();
    */
    return 0;
}


static struct file_operations
ctrl_fops = 
{
    .owner          = THIS_MODULE,
    .open           = hpmmap_open,
    .release        = hpmmap_release,
    .unlocked_ioctl = hpmmap_ioctl,
    .compat_ioctl   = hpmmap_ioctl
};

static const char* current_kprobe_name = "current_kprobe";
static unsigned long __hpmmap_current_kprobe_add=0;
void *__hpmmap_current_kprobe=0;

static char *cur_kprobe = 0;
module_param(cur_kprobe, charp, 0);
MODULE_PARM_DESC(cur_kprobe, "Address of current_kprobe (required)");

int __init 
hpmmap_init(void)
{
    dev_t dev = MKDEV(0, 0);
    int ret   = 0;
    int conversion = 0;
    
    printk("-------------------------------------\n");
    printk("-------------------------------------\n");
    printk("Initializing HPMMAP memory management\n");
    printk("-------------------------------------\n");
    printk("-------------------------------------\n");
    if (!cur_kprobe) {
        printk("ERROR:  the cur_kprobe parameter is required\n");
        return -1;
    }

    __hpmmap_current_kprobe_add = kallsyms_lookup_name_fn(current_kprobe_name);
    __hpmmap_current_kprobe = &__hpmmap_current_kprobe_add;
    /*
    conversion = kstrtoul(cur_kprobe,16,(unsigned long*)&__hpmmap_current_kprobe);
    if (!conversion) {
        printk("ERROR:  kstrtoul of cur_kprobe parameter is unsuccessful\n");
        return -1;
    }
    */
    printk("cur_kprobe = %s  __hpmmap_current_kprobe = %p\n", cur_kprobe, (void*)__hpmmap_current_kprobe);
    
    if (hpmmap_linux_symbol_init() == -1) {
        return -1;
    }

    printk("symbol init done\n");
    
    if (hook_mmap_syscalls() == -1) {
        ret = -1;
        goto err;
    }

    printk("hook mmap syscalls done\n");

    if (init_hpmmap_probes() == -1) {
        ret = -1;
        goto err;
    }

    printk("init probes done\n");

    if (init_hpmmap_ftrace() == -1) {
        ret = -1;
        goto err;
    }

    printk("init ftrace done\n");

    {
        int num_nodes = numa_num_nodes();
        int node_id   = 0;
        
        printk("setting up for %d numa nodes\n", num_nodes);
	
        memzones = kmalloc(sizeof(struct buddy_memzone *) * num_nodes, GFP_KERNEL);
    	printk("allocated\n");

        memset(memzones, 0, sizeof(struct buddy_memzone *) * num_nodes);

        printk("zeroed\n");

        hpmmap_proc_dir = proc_mkdir(PROC_DIR, NULL);

        printk("proc dir configured\n");

        for (node_id = 0; node_id < num_nodes; node_id++) {
            struct buddy_memzone * zone = NULL;

            printk("start buddy init on node %d\n",node_id);
            
            zone = buddy_init(get_order(0x40000000) + PAGE_SHIFT, PAGE_SHIFT, node_id, hpmmap_proc_dir);

            printk("done buddy init on node %d\n",node_id);

            if (zone == NULL) {
                PrintError("Could not initialization memory management for node %d\n", node_id);
                return -1;
            }

            memzones[node_id] = zone;
        }
    }

    hpmmap_class = class_create(THIS_MODULE, DEV_FILENAME);
    
    if (IS_ERR(hpmmap_class)) {
        PrintError("Failed to register HPMMAP class\n");
        ret = PTR_ERR(hpmmap_class);
        goto err;
    }

    ret = alloc_chrdev_region(&dev, 0, 1, DEV_FILENAME);

    if (ret < 0) {
        PrintError("Registering memory controller device\n");
        class_destroy(hpmmap_class);
        goto err;
    }

    major_num = MAJOR(dev);
    dev       = MKDEV(major_num, 0);

    cdev_init(&ctrl_dev, &ctrl_fops);
    ctrl_dev.owner = THIS_MODULE;
    ctrl_dev.ops   = &ctrl_fops; 
    cdev_add(&ctrl_dev, dev, 1);

    device_create(hpmmap_class, NULL, dev, NULL, DEV_FILENAME);

    printk("device file interface configured\n");

    printk("initialization complete\n");

    printk("-------------------------------------\n");

    return 0;

err:
    
    unhook_mmap_syscalls();
    deinit_hpmmap_probes();
    deinit_hpmmap_ftrace();

    return ret;
}


static void __exit
hpmmap_exit(void ) 
{
    dev_t dev = 0;

    deinit_hpmmap_ftrace();
    deinit_hpmmap_probes();
    unhook_mmap_syscalls();

    {
        int num_zones = numa_num_nodes();
        int i         = 0;

        for (i = 0; i < num_zones; i++) {
            buddy_deinit(memzones[i], hpmmap_proc_dir);
        }

        kfree(memzones);
    }

    remove_proc_entry("hpmmap", NULL);

    dev = MKDEV(major_num, 0);

    unregister_chrdev_region(MKDEV(major_num, 0), 1);
    cdev_del(&ctrl_dev);
    device_destroy(hpmmap_class, dev);
    
    class_destroy(hpmmap_class);

    printk("HPMMAP memory management deinitialized\n");
}


module_init(hpmmap_init);
module_exit(hpmmap_exit);
