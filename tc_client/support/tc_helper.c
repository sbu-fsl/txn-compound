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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
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

void tc_copy_attrs(const struct tc_attrs *src, struct tc_attrs *dst)
{
	if (src->masks.has_mode)
		tc_attrs_set_mode(dst, src->mode);
	if (src->masks.has_size)
		tc_attrs_set_size(dst, src->size);
	if (src->masks.has_nlink)
		tc_attrs_set_nlink(dst, src->nlink);
	if (src->masks.has_uid)
		tc_attrs_set_uid(dst, src->uid);
	if (src->masks.has_gid)
		tc_attrs_set_gid(dst, src->gid);
	if (src->masks.has_rdev)
		tc_attrs_set_rdev(dst, src->rdev);
	if (src->masks.has_atime)
		tc_attrs_set_atime(dst, src->atime);
	if (src->masks.has_mtime)
		tc_attrs_set_mtime(dst, src->mtime);
	if (src->masks.has_ctime)
		tc_attrs_set_ctime(dst, src->ctime);
}

bool tc_cmp_file(const tc_file *tcf1, const tc_file *tcf2)
{
	if (tcf1->type != tcf2->type)
		return false;
	switch (tcf1->type) {
	case TC_FILE_DESCRIPTOR:
		return tcf1->fd == tcf2->fd;
	case TC_FILE_PATH:
	case TC_FILE_CURRENT:
		return tcf1->type == tcf2->type &&
		       strcmp(tcf1->path, tcf2->path) == 0;
	case TC_FILE_HANDLE:
		if (tcf1->handle->handle_bytes != tcf2->handle->handle_bytes)
			return false;
		if (tcf1->handle->handle_type != tcf2->handle->handle_type)
			return false;
		return memcmp(tcf1->handle->f_handle,
			      tcf2->handle->f_handle,
			      tcf1->handle->handle_bytes);
	default:
		return true;
	}
};

