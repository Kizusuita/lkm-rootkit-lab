# lkm-rootkit-lab
 
Linux kernel module rootkit for learning; covers ftrace syscall hooking, file/process hiding, and privilege escalation. Run in a VM.
 
> Educational use only. Only load this on a machine you own. IT WILL COMPROMISE YOUR MACHINE.
 
---
 
## What it does
 
| # | Technique | Description |
|---|-----------|-------------|
| 1 | File/directory hiding | Hooks `getdents64`; anything prefixed `rootkit_` disappears from `ls`, `find`, etc. |
| 2 | Process hiding | Same hook; filters `/proc/<pid>` entries from `ps`, `top`, etc. |
| 3 | Module self-hiding | Removes itself from the kernel module list and `/sys/module` |
| 4 | Privilege escalation backdoor | `/proc` entry; write a PID to it and that process gets root |
 
---
 
## How it works
 
### ftrace hooking
The modern way to intercept kernel functions on 5.x+ kernels. Instead of patching the syscall table (which requires disabling CPU write protection via CR0; unreliable and often blocked since 5.3), this uses the kernel's own ftrace infrastructure to redirect execution at function entry.
 
### getdents64
`ls`, `ps`, `find`, and basically every directory-enumeration tool calls `getdents64(2)`. The hook calls the real syscall, copies the result buffer into kernel space, removes any entries that match the hide rules, and copies the filtered buffer back to userspace.
 
### Module self-hiding
`list_del(&THIS_MODULE->list)` splices the module out of the kernel's module linked list; `lsmod` and `/proc/modules` both iterate that list. `kobject_del` removes it from `/sys/module`. The list pointer is saved so it can be re-inserted cleanly on `rmmod`.
 
### Privilege escalation
`prepare_creds()` clones a task's credentials, all UID/GID fields get zeroed, and `commit_creds()` installs the new credentials on the target process. Same API used by `sudo` — just pointed at a process that didn't ask for it.
 
---
 
## Setup
 
```bash
# Rocky Linux / RHEL / Fedora
sudo dnf install kernel-devel-$(uname -r) kernel-headers gcc make
 
# Debian / Ubuntu
sudo apt install linux-headers-$(uname -r) gcc make
```
 
Make sure your kernel headers match `uname -r`. If they don't, install the matching package or reboot into the kernel you have headers for.
 
---
 
## Build & run
 
```bash
cd rootkit
make
sudo insmod rootkit.ko
sudo dmesg | tail -20
```
 
After loading, `lsmod | grep rootkit` returns nothing; it's already hidden.
 
```bash
# Run the demo
sudo bash test/demo.sh
 
# Unload
sudo rmmod rootkit
sudo dmesg | tail -5
```
 
---
 
## Project structure
 
```
lkm-rootkit-lab/
├── rootkit/
│   ├── include/
│   │   └── ftrace_helper.h   ← ftrace hook infrastructure
│   ├── rootkit.c             ← the module
│   └── Makefile
├── detector/                 ← coming soon
├── test/
│   └── demo.sh
└── README.md
```
 
---
 
## References
 
- [The Linux Kernel Module Programming Guide](https://sysprog21.github.io/lkmpg/)
- [xcellerator's rootkit series](https://xcellerator.github.io/tags/rootkit/) — solid ftrace walkthrough
- *Linux Device Drivers* (Corbet, Rubini, Kroah-Hartman)
- `Documentation/trace/ftrace.rst` in the kernel source tree
 
