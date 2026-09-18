/*
 * src/platform/platform_arch.h - CPU architecture flags
 *
 * WHAT: BRIX_ARCH_ARM64 / BRIX_ARCH_X86_64 as 0 or 1 from the compiler's
 *       target macros. This is the instruction set, not the operating system:
 *       every host may test it, and it is the only conditional the PAL
 *       interface keeps outside the host directories.
 */

#ifndef BRIX_PLATFORM_ARCH_H
#define BRIX_PLATFORM_ARCH_H

#if defined(__aarch64__) || defined(__ARM64__) || defined(_M_ARM64)
    #define BRIX_ARCH_ARM64 1
    #define BRIX_ARCH_X86_64 0
#elif defined(__x86_64__) || defined(_M_X64)
    #define BRIX_ARCH_ARM64 0
    #define BRIX_ARCH_X86_64 1
#else
    #define BRIX_ARCH_ARM64 0
    #define BRIX_ARCH_X86_64 0
#endif

#endif /* BRIX_PLATFORM_ARCH_H */
