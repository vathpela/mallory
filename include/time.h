// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * time.h - very simple time helpers
 * Copyright Peter Jones <pjones@redhat.com>
 */

#ifndef SHIM_TIME_H_
#define SHIM_TIME_H_

#include <stdint.h>
#include <efi.h>
#include "compiler.h"

struct timespec {
	uint64_t tv_sec;
	uint32_t tv_nsec;
};

/*
 * given a calendar year (1970-...) and month (1-13), returns how many days
 * were in the prior months of that year.
 */
static inline UNUSED uint32_t
days_before_this_month(uint16_t year, uint8_t month)
{
	uint32_t days = 0;
	switch (month - 1) {
	case 12:
		days += 31;
		/* fall through */
	case 11:
		days += 30;
		/* fall through */
	case 10:
		days += 31;
		/* fall through */
	case 9:
		days += 30;
		/* fall through */
	case 8:
		days += 31;
		/* fall through */
	case 7:
		days += 31;
		/* fall through */
	case 6:
		days += 30;
		/* fall through */
	case 5:
		days += 31;
		/* fall through */
	case 4:
		days += 30;
		/* fall through */
	case 3:
		days += 31;
		/* fall through */
	case 2:
		if (((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0))
			days += 28;
		else
			days += 29;
		/* fall through */
	case 1:
		days += 31;
		/* fall through */
	default:
		/* pacify C's stupid label + statement rule */
		days += 0;
	}

	return days;
}

/*
 * given a calendar year (1970-...) and month (1-13), returns how many
 * tv_sec were in the prior months of that year.
 */
static inline UNUSED uint64_t
tv_sec_before_this_month(uint16_t year, uint8_t month)
{
	return 86400ull * days_before_this_month(year, month);
}

/*
 * given an EFI_TIME, return elapsed time since the unix epoch, ignoring
 * the time zone, DST, and leap tv_sec completely.
 */
static inline UNUSED struct timespec
efi_time_to_timespec(EFI_TIME *time)
{
	struct timespec elapsed = { 0, };
	uint16_t year;

	elapsed.tv_nsec = time->Nanosecond;
	while (elapsed.tv_nsec >= 1000000000ul) {
		elapsed.tv_sec += 1;
		elapsed.tv_nsec -= 999999999ul;
	}
	elapsed.tv_sec += time->Second;
	elapsed.tv_sec += time->Minute * 60ul;
	elapsed.tv_sec += time->Hour * 3600ul;
	elapsed.tv_sec += (time->Day - 1) * 86400ull;

	elapsed.tv_sec += tv_sec_before_this_month(time->Year, time->Month);

	for (year = time->Year - 1; year > 1969; year--)
		elapsed.tv_sec += tv_sec_before_this_month(year, 13);

	return elapsed;
}

/*
 * returns the elapsed time between two timespecs
 */
static inline UNUSED struct timespec
subtract_timespec(struct timespec *earlier, struct timespec *later)
{
	struct timespec ret = {
		.tv_sec = later->tv_sec - earlier->tv_sec,
		.tv_nsec = 0,
	};

	if (later->tv_nsec < earlier->tv_nsec) {
		ret.tv_sec -= 1;
		ret.tv_nsec += 1000000000ull;
	}
	ret.tv_nsec += later->tv_nsec;
	ret.tv_nsec -= earlier->tv_nsec;

	return ret;
}

#endif /* !SHIM_TIME_H_ */
// vim:fenc=utf-8:tw=75:noet
