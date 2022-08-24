// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * globals.c - global shim state
 * Copyright Peter Jones <pjones@redhat.com>
 */

#include "shim.h"

UINT32 vendor_authorized_size = 0;
UINT8 *vendor_authorized = NULL;

UINT32 vendor_deauthorized_size = 0;
UINT8 *vendor_deauthorized = NULL;

UINT32 user_cert_size;
UINT8 *user_cert;

/*
 * indicator of how an image has been verified
 */
verification_method_t verification_method;
int loader_is_participating;

UINT8 user_insecure_mode;
UINT8 ignore_db;
UINT8 trust_mok_list;
UINT8 mok_policy = 0;

UINT32 verbose = 0;

// vim:fenc=utf-8:tw=75:noet
