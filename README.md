<<<<<<< HEAD
<<<<<<< HEAD
Proof of Concept: Silent eBPF Neutralization via Initramfs Injection
=======
# initramfs-file-access-poc
=======
#  bpf_blinder 🛡️👻
>>>>>>> b06a8a4 (bpf_blinder code and docs)

Proof of Concept: Silent eBPF Neutralization via Initramfs Injection

## 📖 About The Project

bpf_blinder is a Linux Kernel Module (LKM) developed for academic research. It demonstrates a critical architectural vulnerability in the Linux boot process: the "Time Gap" between kernel initialization and the loading of userspace security agents.

By injecting this rootkit during the early boot stages (Initramfs), an attacker can completely and silently disable the eBPF subsystem before any monitoring tool (like Falco, Tetragon, or Cilium) is loaded. The module intercepts the sys_bpf system call and blocks BPF_PROG_LOAD commands, returning a "Fake Success" status. This causes security tools to believe they are operational while receiving no data from the kernel.

## ⚠️ Legal Disclaimer & Warning

## READ CAREFULLY BEFORE USE

This software is for EDUCATIONAL AND ACADEMIC RESEARCH PURPOSES ONLY.

This code performs direct manipulation of kernel memory and CPU registers (CR0).

It is designed to run EXCLUSIVELY in isolated Virtual Machines (VMs).

Running this on a production system or physical hardware may cause irreversible system crashes (Kernel Panic) and data corruption.

<<<<<<< HEAD
In this research context, /dev/kmsg provides a persistent and verifiable way to record evidence of actions that occur during the initramfs stage.
Because the kernel log survives through the boot process, messages written at this early stage remain visible after the system has fully booted, allowing researchers to confirm that the PoC executed successfully before any userspace or eBPF-based monitoring began.
>>>>>>> e6ad387 (Create README.md)
=======
The authors are not responsible for any damage caused by the misuse of this software.

# 📋 Prerequisites

To successfully compile and run this module, ensure your environment meets the following criteria:

Operating System: Linux (Ubuntu 20.04 recommended for compatibility).

Kernel Version:

Recommended: Kernel 5.4 or lower.

Note: Newer kernels (5.7+) unexport kallsyms_lookup_name, requiring advanced bypass techniques not included in this basic PoC.

Permissions: Root (sudo) access is required to insert kernel modules.

Install Dependencies

Update your package list and install the necessary build tools:

sudo apt update
sudo apt install build-essential linux-headers-$(uname -r)



## 🛠️ Installation & Build

Clone the repository (or download the source files):

bpf_blinder.c

Makefile

Compile the module:
Run the make command in the project directory:

make



Expected Outcome: A bpf_blinder.ko file will be created.

## 🚀 Usage

1. Load the Module (The Attack)

Insert the module into the kernel to activate the hook. This simulates the attacker's action during the Initramfs stage.

sudo insmod bpf_blinder.ko



2. Verify Hook Installation

Check the kernel ring buffer to confirm the hook is active and the sys_call_table was modified.

sudo dmesg | tail



Output: [Rootkit] Hook installed. eBPF is now blind.

3. Test eBPF Blindness

At this point, try running any eBPF-based tool (e.g., loading a simple BPF program). The tool should report success (receiving a fake FD), but no program will actually be loaded into the kernel.

4. Unload and Restore (Cleanup)

Remove the module to unhook the function and restore original system behavior.

sudo rmmod bpf_blinder



Output: [Rootkit] Hook removed. Original BPF restored.

## 🔧 Technical Details

The module operates by:

Locating the Syscall Table: Using kallsyms_lookup_name to find sys_call_table in memory.

Disabling Write Protection: Modifying the CR0 register (flipping the WP bit) to allow writing to read-only memory.

Hooking: Replacing the function pointer at index __NR_bpf with the malicious hook_sys_bpf function.

Restoring Protections: Resetting the CR0 register to avoid system instability.

## 🧠 Code Highlights

Key kernel programming concepts demonstrated in this module:

MODULE_LICENSE("GPL"): This macro is crucial. It declares the module as GPL-licensed, granting it access to restricted kernel symbols (like kallsyms_lookup_name in some versions) and preventing "Kernel Taint" warnings.

__init Macro: Used on the initialization function (my_rootkit_init). It tells the kernel to discard this function from memory once the module is loaded, saving RAM.

CR0 Register Manipulation: The code explicitly toggles the Write Protect (WP) bit (Bit 16) in the CR0 control register. This bypasses the hardware protection that normally prevents writing to the read-only sys_call_table. Note: This specific action triggers a VMExit in hypervisors, making it detectable by VMI-based security.

## 📝 License

Distributed under the GPL v2 License. See LICENSE for more information.
>>>>>>> b06a8a4 (bpf_blinder code and docs)
