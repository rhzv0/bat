#ifndef BAT_FTRACE_HELPER_H
#define BAT_FTRACE_HELPER_H

#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include "../include/arch.h"

/* ARM64 requires PTREGS_SYSCALL_STUBS just like x86_64 */
#if (defined(CONFIG_X86_64) || defined(CONFIG_ARM64)) && \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
extern struct kprobe kp;
#endif

#define HOOK(_name, _hook, _orig) \
    { .name = (_name), .function = (_hook), .original = (_orig), }

/* USE_FENTRY_OFFSET=0 avoids crashes in kernels 6.12+ */
#define USE_FENTRY_OFFSET 0
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;
    unsigned long address;
    struct ftrace_ops ops;
};

int  fh_resolve_hook_address(struct ftrace_hook *hook);
void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                              struct ftrace_ops *ops, struct pt_regs *regs);
int  fh_install_hook(struct ftrace_hook *hook);
void fh_remove_hook(struct ftrace_hook *hook);
int  fh_install_hooks(struct ftrace_hook *hooks, size_t count);
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count);

unsigned long *resolve_sym(const char *symname);

#endif /* BAT_FTRACE_HELPER_H */
