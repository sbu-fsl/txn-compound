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

#ifndef __TC_HELPER_H__
#define __TC_HELPER_H__

#include "tc_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Free an array of tc_iovec.
 */
void free_iovec(struct tc_iovec *iovec, int count);

/**
 * Compare the data contents of two arrays of tc_iovec.
 *
 * Return whether the two arrays have the same contents.
 */
bool compare_content(struct tc_iovec *iovec1, struct tc_iovec *iovec2,
		     int count);

#ifdef __cplusplus
}
#endif

#endif // __TC_HELPER_H__
