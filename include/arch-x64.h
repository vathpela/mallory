// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * arch-x64.h - x64 setup
 * Copyright Peter Jones <pjones@redhat.com>
 */

#ifndef SHIM_ARCH_X64_H_
#define SHIM_ARCH_X64_H_
#ifdef __x86_64__

#define EFI_ARCH_CHAR8 "x64"
#define MDE_CPU_X64 1
#define PAGE_SIZE 4096

/* shim.h will check if the compiler is new enough in some other CU */
#if !defined(GNU_EFI_USE_EXTERNAL_STDARG)
#define GNU_EFI_USE_EXTERNAL_STDARG
#endif

#if !defined(GNU_EFI_USE_MS_ABI)
#define GNU_EFI_USE_MS_ABI
#endif

#ifdef NO_BUILTIN_VA_FUNCS
#undef NO_BUILTIN_VA_FUNCS
#endif

#endif
#endif /* !SHIM_ARCH_X64_H_ */
// vim:fenc=utf-8:tw=75:noet
