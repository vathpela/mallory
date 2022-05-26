// SPDX-License-Identifier: BSD-2-Clause-Patent
#ifdef SHIM_UNIT_TEST
#include_next <inttypes.h>
#else
#ifndef _INTTYPES_H
#define _INTTYPES_H

#include <stddef.h>
#include <stdint.h>

#if __SIZEOF_LONG__ == 8
#define PRIu64	"lu"
#define PRIx64	"lx"
#define PRId64	"ld"
#else
#define PRIu64	"llu"
#define PRIx64	"llx"
#define PRId64	"lld"
#endif
#define PRIu32	"u"
#define PRIx32	"x"
#define PRId32	"d"

#endif /* !INTTYPES_H_ */
#endif
// vim:fenc=utf-8:tw=75:noet
