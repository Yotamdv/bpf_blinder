# 🛡️ bpf_blinder (Ftrace Edition)

Proof of Concept: Silent eBPF Neutralization via Ftrace Hooking

## 📖 About The Project

bpf_blinder is a Linux Kernel Module (LKM) developed for academic research. It demonstrates how an attacker can leverage the kernel's built-in debugging infrastructure (`ftrace`) to silently neutralize security monitoring tools.

Unlike traditional rootkits that modify the System Call Table directly (triggering memory protection warnings), this module uses `ftrace` with `IPMODIFY` flags to redirect execution flow. It intercepts the `sys_bpf` system call and blocks `BPF_PROG_LOAD` commands, returning a "Fake Success" status. This blinds tools like Falco or Tetragon without causing system instability.

## ⚠️ Legal Disclaimer & Warning

**EDUCATIONAL AND ACADEMIC RESEARCH PURPOSES ONLY.**

This code manipulates kernel execution flow. While safer than CR0 modification, it still runs in kernel space. The authors are not responsible for any misuse or damage.

## 📋 Prerequisites

* **Operating System:** Linux (Ubuntu 20.04 / Kernel 5.4 recommended).
* **Kernel Config:** Requires `CONFIG_FTRACE` and `CONFIG_KPROBES` (enabled by default on most distros).
* **Permissions:** Root access.

### 🔍 How to Verify `kallsyms_lookup_name` Availability

Before compiling, you can check if your kernel exports the helper function required to find symbols. This module includes a fallback mechanism (using Kprobes), but you can verify the status manually:

Run the following command:
```bash
grep " kallsyms_lookup_name" /boot/System.map-$(uname -r)