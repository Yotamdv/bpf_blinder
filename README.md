<<<<<<< HEAD
Proof of Concept: Silent eBPF Neutralization via Initramfs Injection
=======
# initramfs-file-access-poc

## Overview

This repository contains a minimal PoC that demonstrates code running in the initramfs stage can write to /dev/kmsg before userspace or eBPF-based syscall monitors are active, illustrating an early-boot visibility gap.

## Contents

Main artifact: main.cpp (simple program that writes a single kernel log line). Build helper: Makefile (dynamic build; static build only on Linux with static libs).

## Build & Run

Compile on a suitable Linux environment and run as root or from initramfs so /dev/kmsg is available. Verify the message via dmesg or journalctl -k after boot.

## Research context

The PoC shows that basic syscalls (open/write) executed in initramfs can produce observable effects before userspace monitoring is initialized, supporting the argument that hypervisor-level monitoring offers earlier and more complete visibility.

## About /dev/kmsg

/dev/kmsg is a special kernel interface that allows userspace (and early boot environments such as initramfs) to write messages directly into the kernel’s log buffer.
These messages are stored inside the kernel ring buffer and can later be viewed using standard tools such as dmesg or journalctl -k.

In this research context, /dev/kmsg provides a persistent and verifiable way to record evidence of actions that occur during the initramfs stage.
Because the kernel log survives through the boot process, messages written at this early stage remain visible after the system has fully booted, allowing researchers to confirm that the PoC executed successfully before any userspace or eBPF-based monitoring began.
>>>>>>> e6ad387 (Create README.md)
