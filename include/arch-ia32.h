// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * arch-ia32.h - ia32 setup
 */

#ifndef SHIM_ARCH_IA32_H_
#define SHIM_ARCH_IA32_H_
#if defined(__i686__) || defined(__i386__)

#define EFI_ARCH_CHAR8 "ia32"
#define MDE_CPU_IA32 1
#define PAGE_SIZE 4096

#endif
#endif /* !SHIM_ARCH_IA32_H_ */
// vim:fenc=utf-8:tw=75:noet
