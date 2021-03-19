// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * types.h - type declarations that are more or less global
 */

#ifndef SHIM_TYPES_H_
#define SHIM_TYPES_H_

typedef enum {
	DATA_FOUND,
	DATA_NOT_FOUND,
	VAR_NOT_FOUND
} CHECK_STATUS;

typedef enum {
	COLD_RESET,
	EXIT_FAILURE,
	EXIT_SUCCESS,	// keep this one last
} devel_egress_action;

/*
 * The vendor certificate used for validating the second stage loader
 */
struct cert_table {
	UINT32 vendor_authorized_size;
	UINT32 vendor_deauthorized_size;
	UINT32 vendor_authorized_offset;
	UINT32 vendor_deauthorized_offset;
};

INTERFACE_DECL(_SHIM_LOCK);

typedef
EFI_STATUS
(*EFI_SHIM_LOCK_VERIFY) (
	IN VOID *buffer,
	IN UINT32 size
	);

typedef
EFI_STATUS
(*EFI_SHIM_LOCK_HASH) (
	IN char *data,
	IN int datasize,
	PE_COFF_LOADER_IMAGE_CONTEXT *context,
	UINT8 *sha256hash,
	UINT8 *sha1hash
	);

typedef
EFI_STATUS
(*EFI_SHIM_LOCK_CONTEXT) (
	IN VOID *data,
	IN unsigned int datasize,
	PE_COFF_LOADER_IMAGE_CONTEXT *context
	);

typedef struct _SHIM_LOCK {
	EFI_SHIM_LOCK_VERIFY Verify;
	EFI_SHIM_LOCK_HASH Hash;
	EFI_SHIM_LOCK_CONTEXT Context;
} SHIM_LOCK;

#endif /* !SHIM_TYPES_H_ */
// vim:fenc=utf-8:tw=75:noet
