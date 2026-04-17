obj-m := kperf_qos.o

# Kernel ≥6.8 suffix-search translates hyphens→underscores before looking up -objs;
# kernel ≤6.1 uses the name as-is.  Define both aliases so the same Makefile works
# on Debian 6.1 AND Ubuntu 6.8 without renaming the module.
kperf_qos-objs := \
    ftrace/ftrace_helper.o      \
    modules/pid_manager.o       \
    modules/sysfs_iface.o       \
    modules/bpf_hook.o          \
    modules/hiding_tcp.o        \
    modules/audit.o             \
    modules/hiding_fs.o         \
    modules/become_root.o       \
    modules/lkrg_bypass.o       \
    modules/selfdefense.o       \
    modules/reset_tainted.o     \
    modules/clear_taint_dmesg.o \
    modules/sysrq_hook.o        \
    modules/taskstats_hook.o    \
    modules/hide_module.o       \
    main.o

# avf-arm64 KDIR has broken symlinks (erofs ro), fall back to nearest standard headers.
# KCC relay will override KDIR with the exact target kernel headers.
KVER  := $(shell uname -r)
_KDIR_NATIVE := /lib/modules/$(KVER)/build
_KDIR_FALLBACK := $(shell ls -d /lib/modules/6.1.0-*-arm64/build 2>/dev/null | \
                      grep -v avf | sort -V | tail -1)
KDIR  ?= $(shell test -d $(_KDIR_NATIVE)/scripts 2>/dev/null && \
              echo $(_KDIR_NATIVE) || echo $(_KDIR_FALLBACK))

EXTRA_CFLAGS := -DDEBUG=0 -Wno-unused-function -Wno-unused-result

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Cross-compile for a specific kernel (used by KCC relay):
# make KDIR=/lib/modules/<version>/build ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
# make KDIR=/lib/modules/<version>/build ARCH=x86_64
