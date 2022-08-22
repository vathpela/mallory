// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * verify.h - verify a loaded binary
 *
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc
 */

#ifndef SHIM_VERIFY_H_
#define SHIM_VERIFY_H_

#include <efi.h>
#include "peimage.h"

void drain_openssl_errors(void);
EFI_STATUS verify_buffer_authenticode (char *data, int datasize,
				       PE_COFF_LOADER_IMAGE_CONTEXT *context,
				       UINT8 *sha256hash, UINT8 *sha1hash);
void init_openssl(void);

#endif /* !SHIM_VERIFY_H_ */
// vim:fenc=utf-8:tw=75:noet
