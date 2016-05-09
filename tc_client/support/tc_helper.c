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
#include "tc_helper.h"

#include <stdio.h>
#include <linux/limits.h>
#include <libgen.h>
#include "tc_api.h"

void free_iovec(struct tc_iovec *iovec, int count)
{
	int i = 0;

	while (i < count) {
		free(iovec[i].data);
		i++;
	}

	free(iovec);
}

char *get_tc_config_file(char *buf, int buf_size)
{
	char path[PATH_MAX];
	readlink("/proc/self/exe", path, PATH_MAX);
	snprintf(buf, buf_size,
		 "%s/../../../config/tc.ganesha.conf", dirname(path));
	return buf;
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

struct file_handle *new_file_handle(size_t fh_len, char *fh_val)
{
	struct file_handle *fh = malloc(sizeof(*fh) + fh_len);
	if (fh) {
		fh->handle_bytes = fh_len;
                fh->handle_type = FILEID_NFS_FH_TYPE;
                memmove(fh->f_handle, fh_val, fh_len);
        }
	return fh;
}

void del_file_handle(struct file_handle *fh)
{
	free(fh);
}
