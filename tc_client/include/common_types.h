/**
 * Copyright (C) Stony Brook University 2016
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

#ifndef __TC_UTIL_TYPES_H__
#define __TC_UTIL_TYPES_H__

#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	char *data;
	size_t size;
} buf_t;

static inline buf_t new_buf(char *b, size_t s)
{
	buf_t buf;
	buf.data = b;
	buf.size = s;
	return buf;
}

typedef struct {
	const char *data;
	size_t size;
} slice_t;

static inline slice_t new_slice(const char *d, size_t s)
{
	slice_t sl;
	sl.data = d;
	sl.size = s;
	return sl;
}

static inline slice_t toslice(const char *d)
{
	slice_t sl;
	sl.data = d;
	sl.size = strlen(d);
	return sl;
}

#ifdef __cplusplus
}
#endif

#endif  // __TC_UTIL_TYPES_H__
