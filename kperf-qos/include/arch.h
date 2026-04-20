/* arch.h   multi-arch abstraction for bat-stealth
 * Supports x86_64 and ARM64 (aarch64).
 * ARCH_SYS(name) : syscall entry point symbol name
 * REGS_ARGn(regs): syscall argument accessor from pt_regs
 */
#ifndef BAT_ARCH_H
#define BAT_ARCH_H

#include <linux/version.h>

#ifdef CONFIG_X86_64

#define ARCH_SYS(name)     "__x64_sys_" name
#define ARCH_SYS_IA32(name) "__ia32_sys_" name
#define REGS_ARG0(regs)    ((regs)->di)
#define REGS_ARG1(regs)    ((regs)->si)
#define REGS_ARG2(regs)    ((regs)->dx)
#define REGS_ARG3(regs)    ((regs)->r10)
#define REGS_ARG4(regs)    ((regs)->r8)
#define REGS_ARG5(regs)    ((regs)->r9)

#elif defined(CONFIG_ARM64)

#define ARCH_SYS(name)     "__arm64_sys_" name
#undef  ARCH_SYS_IA32        /* ia32 does not exist on ARM64 */
#define REGS_ARG0(regs)    ((regs)->regs[0])
#define REGS_ARG1(regs)    ((regs)->regs[1])
#define REGS_ARG2(regs)    ((regs)->regs[2])
#define REGS_ARG3(regs)    ((regs)->regs[3])
#define REGS_ARG4(regs)    ((regs)->regs[4])
#define REGS_ARG5(regs)    ((regs)->regs[5])

#else
#error "bat-stealth: unsupported architecture (x86_64 and ARM64 only)"
#endif

/* PC register for ftrace ip-redirect */
#ifdef CONFIG_X86_64
#define REGS_SET_PC(regs, addr)  ((regs)->ip = (unsigned long)(addr))
#elif defined(CONFIG_ARM64)
#define REGS_SET_PC(regs, addr)  ((regs)->pc = (unsigned long)(addr))
#endif

#endif /* BAT_ARCH_H */
