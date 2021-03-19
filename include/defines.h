// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * defines.h - cpp definitions that apply everywhere
 */

#ifndef SHIM_DEFINES_H_
#define SHIM_DEFINES_H_

#define EFI_IMAGE_SECURITY_DATABASE_GUID { 0xd719b2cb, 0x3d3a, 0x4596, { 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f }}

#define VERSION as_lstring(VERSION_CHAR8)
#define DASHRELEASE as_lstring(DASHRELEASE_CHAR8)

#ifndef EFI_ARCH
#define EFI_ARCH as_lstring(EFI_ARCH_CHAR8)
#endif

#ifndef DEFAULT_LOADER_CHAR
#define DEFAULT_LOADER_CHAR "\\grub" EFI_ARCH_CHAR8 ".efi"
#endif
#ifndef DEFAULT_LOADER
#define DEFAULT_LOADER as_lstring(EFI_ARCH_CHAR8)
#endif

#ifndef DEBUGDIR
#define DEBUGDIR L"/usr/lib/debug/usr/share/shim/" EFI_ARCH L"-" VERSION DASHRELEASE L"/"
#endif
#ifndef DEBUGSRC
#define DEBUGSRC L"/usr/src/debug/shim-" VERSION DASHRELEASE L"." EFI_ARCH L"/"
#endif

#define FALLBACK L"\\fb" EFI_ARCH L".efi"
#define MOK_MANAGER L"\\mm" EFI_ARCH L".efi"

#if defined(VENDOR_DB_FILE)
# define vendor_authorized vendor_db
# define vendor_authorized_size vendor_db_size
# define vendor_authorized_category VENDOR_ADDEND_DB
#elif defined(VENDOR_CERT_FILE)
# define vendor_authorized vendor_cert
# define vendor_authorized_size vendor_cert_size
# define vendor_authorized_category VENDOR_ADDEND_X509
#else
# define vendor_authorized vendor_null
# define vendor_authorized_size vendor_null_size
# define vendor_authorized_category VENDOR_ADDEND_NONE
#endif

#if defined(VENDOR_DBX_FILE)
# define vendor_deauthorized vendor_dbx
# define vendor_deauthorized_size vendor_dbx_size
#else
# define vendor_deauthorized vendor_deauthorized_null
# define vendor_deauthorized_size vendor_deauthorized_null_size
#endif

#endif /* !SHIM_DEFINES_H_ */
// vim:fenc=utf-8:tw=75:noet
