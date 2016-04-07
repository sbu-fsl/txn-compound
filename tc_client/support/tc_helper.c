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

#include "tc_api.h"
#include "tc_helper.h"

void free_iovec(struct tc_iovec *iovec, int count)
{
	int i = 0;

	while (i < count) {
		free(iovec[i].data);
		i++;
	}

	free(iovec);
}

bool compare_content(struct tc_iovec *iovec1, struct tc_iovec *iovec2,
		     int count)
{
	int i = 0;

	while (i < count) {
		if (iovec1[i].length != iovec2[i].length ||
		    memcmp(iovec1[i].data, iovec2[i].data, iovec1[i].length))
			return false;

		i++;
	}

	return true;
}

