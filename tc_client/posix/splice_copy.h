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
 */
#ifndef __TC_POSIX_SPLICE_COPY__
#define __TC_POSIX_SPLICE_COPY__

#include <sys/types.h>

ssize_t splice_copy_file(const char *src, size_t offset, size_t count,
			 const char *dst);

ssize_t splice_copy(const char *src, size_t src_offset, const char *dst,
		     size_t dst_offset, size_t count);

ssize_t splice_fcopy(int srcfd, size_t src_offset, int dstfd,
		     size_t dst_offset, size_t count);

#endif  // __TC_POSIX_SPLICE_COPY__
