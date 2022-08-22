// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * protocol_v1.h - the shim protocol v1
 * Copyright Peter Jones <pjones@redhat.com>
 */

#ifndef PROTOCOL_V1_H_
#define PROTOCOL_V1_H_

#include <efi.h>
#include "peimage.h"

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

EFI_STATUS install_protocol_v1(void);
void unregister_protocol_v1(void);

#endif /* !PROTOCOL_V1_H_ */
// vim:fenc=utf-8:tw=75:noet
