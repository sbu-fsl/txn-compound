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

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	const size_t capacity;
	size_t size;
	char *data;
} buf_t;

typedef struct {
	size_t size;
	const char *data;
} slice_t;

#define BUF_INITIALIZER(b, c)                                                  \
	{                                                                      \
		.capacity = (c), .size = 0ULL, .data = (b),                    \
	}

static inline buf_t mkbuf(char *b, size_t c)
{
	buf_t buf = BUF_INITIALIZER(b, c);
	return buf;
}

static inline buf_t *init_buf(void *rawbuf, size_t c)
{
	if (!rawbuf)
		return NULL;
	buf_t *pbuf = (buf_t *)rawbuf;
	*((size_t *)&pbuf->capacity) = c;
	pbuf->size = 0;
	pbuf->data = ((char *)rawbuf) + sizeof(buf_t);
	return pbuf;
}

static inline buf_t *new_buf(size_t c)
{
	return init_buf(malloc(sizeof(buf_t) + c), c);
}

static void del_buf(buf_t *pbuf)
{
	free(pbuf);
}

/**
 * A buffer allocated on stack and will be freed automatically once out of
 * scope.  Usage:
 *
 *	buf_t *abuf = new_auto_buf(c);
 *
 * Note: "c" must NOT be an expression with side-effects like "++i".
 */
#define new_auto_buf(c) init_buf(alloca((c) + sizeof(buf_t)), (c))

static inline slice_t mkslice(const char *d, size_t s)
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
	sl.size = d ? strlen(d) : 0;
	return sl;
}

static inline slice_t asslice(const buf_t *pbuf)
{
	return mkslice(pbuf->data, pbuf->size);
}

static inline int buf_append_slice(buf_t *pbuf, slice_t sl)
{
	if (pbuf->size + sl.size > pbuf->capacity) {
		return -1;
	}
	if (pbuf->data + pbuf->size != sl.data)
		memmove(pbuf->data + pbuf->size, sl.data, sl.size);
	pbuf->size += sl.size;
	return sl.size;
}

static inline int buf_append_str(buf_t *pbuf, const char *s)
{
	return buf_append_slice(pbuf, toslice(s));
}

static inline int buf_append_buf(buf_t *dst, const buf_t *src)
{
	return buf_append_slice(dst, asslice(src));
}

static inline int buf_append_char(buf_t *pbuf, char c)
{
	if (pbuf->capacity <= pbuf->size) {
		assert(pbuf->capacity == pbuf->size);
		return -1;
	}
	pbuf->data[pbuf->size++] = c;
	return 1;
}

static inline bool buf_append_null(buf_t *pbuf)
{
	int res = buf_append_char(pbuf, 0);
	if (res >= 0) {
		// The ending '\0' should not be counted.
		--pbuf->size;
		--res;
	}
	return res >= 0;
}

static inline char *asstr(buf_t *pbuf)
{
	return buf_append_null(pbuf) ? pbuf->data : NULL;
}

static inline char *buf_end(buf_t *pbuf)
{
	return pbuf->data + pbuf->size;
}

static inline int buf_remaining(const buf_t *pbuf)
{
	return pbuf->capacity - pbuf->size;
}

static inline buf_t *buf_reset(buf_t *pbuf)
{
	pbuf->size = 0;
	return pbuf;
}

#ifdef __cplusplus
}
#endif

#endif  // __TC_UTIL_TYPES_H__
