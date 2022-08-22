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

#endif /* !SHIM_TYPES_H_ */
// vim:fenc=utf-8:tw=75:noet
