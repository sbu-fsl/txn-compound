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

#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <assert.h>
#include "tc_api.h"
#include "posix/tc_impl_posix.h"
#include "nfs4/tc_impl_nfs4.h"

static tc_res TC_OKAY = { .okay = true, .index = -1, .err_no = 0, };

static bool TC_IMPL_IS_NFS4 = false;

/* Not thread-safe */
void *tc_init(const char *config_path, const char *log_path, uint16_t export_id)
{
	TC_IMPL_IS_NFS4 = (config_path !=  NULL);
	if (TC_IMPL_IS_NFS4) {
		return nfs4_init(config_path, log_path, export_id);
	} else {
		return posix_init(config_path, log_path);
	}
}

void tc_deinit(void *module)
{
	if (TC_IMPL_IS_NFS4) {
		nfs4_deinit(module);
	}
}

tc_file tc_open_by_path(int dirfd, const char *pathname, int flags, mode_t mode)
{
        return posix_open(pathname, flags);
}

tc_res tc_readv(struct tc_iovec *reads, int count, bool is_transaction)
{
	/**
	 * TODO: check if the functions should use posix or TC depending on the
	 * back-end file system.
	 */
	if (TC_IMPL_IS_NFS4) {
		return nfs4_readv(reads, count, is_transaction);
	} else {
		return posix_readv(reads, count, is_transaction);
	}
}

tc_res tc_writev(struct tc_iovec *writes, int count, bool is_transaction)
{
	if (TC_IMPL_IS_NFS4) {
		return nfs4_writev(writes, count, is_transaction);
	} else {
		return posix_writev(writes, count, is_transaction);
	}
}

tc_res tc_getattrsv(struct tc_attrs *attrs, int count, bool is_transaction)
{
	if (TC_IMPL_IS_NFS4) {
		return nfs4_getattrsv(attrs, count, is_transaction);
	} else {
		return posix_getattrsv(attrs, count, is_transaction);
	}
}

tc_res tc_setattrsv(struct tc_attrs *attrs, int count, bool is_transaction)
{
	if (TC_IMPL_IS_NFS4) {
		return nfs4_setattrsv(attrs, count, is_transaction);
	} else {
		return posix_setattrsv(attrs, count, is_transaction);
	}
}

void tc_free_attrs(struct tc_attrs *attrs, int count, bool free_path)
{
	int i;

	if (free_path) {
		for (i = 0; i < count; ++i) {
			if (attrs[i].file.type == TC_FILE_PATH)
				free((char *)attrs[i].file.path);
		}
	}
	free(attrs);
}

tc_res tc_listdir(const char *dir, struct tc_attrs_masks masks, int max_count,
		  struct tc_attrs **contents, int *count)
{
	return posix_listdir(dir, masks, max_count, contents, count);
}

tc_res tc_renamev(tc_file_pair *pairs, int count, bool is_transaction)
{
	return posix_renamev(pairs, count, is_transaction);
}

tc_res tc_removev(tc_file *files, int count, bool is_transaction)
{
	return posix_removev(files, count, is_transaction);
}

tc_res tc_mkdirv(struct tc_attrs *dirs, int count, bool is_transaction)
{
	int i;

	for (i = 0; i < count; ++i) {
		assert(dirs[i].masks.has_mode);
	}
	if (TC_IMPL_IS_NFS4) {
		return nfs4_mkdirv(dirs, count, is_transaction);
	} else {
		return posix_mkdirv(dirs, count, is_transaction);
	}
}

tc_res tc_copyv(struct tc_extent_pair *pairs, int count, bool is_transaction)
{
	return TC_OKAY;
}

tc_res tc_write_adb(struct tc_adb *patterns, int count, bool is_transaction)
{
	return TC_OKAY;
}
