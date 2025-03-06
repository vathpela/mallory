// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * debug.h - debugging support functions
 * Copyright Peter Jones <pjones@redhat.com>
 */

#pragma once

#include <stdint.h>

struct scn {
	char name[9];
	uintptr_t addr;
};

extern void debug_hook(CHAR16 *dbg_var_name, EFI_GUID dbg_var_guid,
		       CHAR16 *file_name, struct scn scns[]);

// vim:fenc=utf-8:tw=75:noet
