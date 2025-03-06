// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * debug.c - debugging support functions
 * Copyright Peter Jones <pjones@redhat.com>
 */

#include "shim.h"

static void
__attribute__((__optimize__("0")))
debug_wait(CHAR16 *dbg_var_name, EFI_GUID dbg_var_guid)
{
	static volatile UINTN x = 0;

	console_print(L"Pausing for debugger attachment.\n");
	console_print(L"To disable this, remove the EFI variable %s-%g .\n",
		      dbg_var_name, &dbg_var_guid);
	x = 1;
	while (x++) {
		/* Make this so it can't /totally/ DoS us. */
#if defined(__x86_64__) || defined(__i386__) || defined(__i686__)
		if (x > 4294967294ULL)
			break;
#elif defined(__aarch64__)
		if (x > 1000)
			break;
#else
		if (x > 12000)
			break;
#endif
		wait_for_debug();
	}

	x = 1;
}

void
__attribute__((__optimize__("0")))
debug_hook(CHAR16 *dbg_var_name, EFI_GUID dbg_var_guid,
	   CHAR16 *file_name, struct scn scns[])
{
	UINT8 *data = NULL;
	UINTN dataSize = 0;
	EFI_STATUS efi_status;
	UINTN i;
	uintptr_t text = 0;

	efi_status = get_variable(dbg_var_name, &data, &dataSize,
				  dbg_var_guid);
	if (EFI_ERROR(efi_status)) {
		dprint(L"Could not load variable %s-%g: %r\n", dbg_var_name, dbg_var_guid, efi_status);
		return;
	}

	FreePool(data);

	for (i = 0; scns[i].name[0] != '\0'; i++) {
		if (CompareMem(scns[i].name, ".text\0\0\0", sizeof(scns[i].name)) == 0)
			text = scns[i].addr;
	}

	dprint(L"add-symbol-file %s 0x%llx", file_name, text);
	for (i = 0; scns[i].name[0] != '\0'; i++) {
		if (CompareMem(scns[i].name, ".text\0\0\0", sizeof(scns[i].name)) == 0)
			continue;
		if (scns[i].addr == 0)
			continue;
		dprint_(L" -s %a 0x%llx", scns[i].name, scns[i].addr);
	}
	dprint_(L"\n");

	debug_wait(dbg_var_name, dbg_var_guid);
}

// vim:fenc=utf-8:tw=75:noet
