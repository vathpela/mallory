// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * time.c - some very simple time helpers
 * Copyright Peter Jones <pjones@redhat.com>
 */

#include "shim.h"

static struct timespec boot_time = {0, };

struct timespec
time_since_boot(void)
{
	EFI_TIME now = { 0, };
	EFI_TIME_CAPABILITIES caps = { 0, };
	EFI_STATUS efi_status;
	struct timespec elapsed = {0, 0};

	if (!RT || !RT->GetTime)
		return elapsed;

	efi_status = RT->GetTime(&now, &caps);
	if (EFI_ERROR(efi_status))
		return elapsed;

	if (boot_time.tv_sec == 0 && boot_time.tv_nsec == 0) {
		boot_time = efi_time_to_timespec(&now);
		return elapsed;
	}

	elapsed = efi_time_to_timespec(&now);
	elapsed = subtract_timespec(&boot_time, &elapsed);
	return elapsed;
}

// vim:fenc=utf-8:tw=75:noet
