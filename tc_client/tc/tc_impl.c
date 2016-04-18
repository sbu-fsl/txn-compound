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

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <assert.h>
#include "tc_api.h"
#include "posix/tc_impl_posix.h"
#include "nfs4/tc_impl_nfs4.h"
#include "path_utils.h"

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

tc_res tc_listdir(const char *dir, struct tc_attrs_masks masks, int max_count,
		  struct tc_attrs **contents, int *count)
{
	if (TC_IMPL_IS_NFS4) {
		return nfs4_listdir(dir, masks, max_count, contents, count);
	} else {
		return posix_listdir(dir, masks, max_count, contents, count);
	}
}

tc_res tc_listdirv(const char **dirs, int count, struct tc_attrs_masks masks,
		   int max_entries, tc_listdirv_cb cb, void *cbarg,
		   bool is_transaction)
{
	return nfs4_listdirv(dirs, count, masks, max_entries, cb, cbarg,
			     is_transaction);
}

tc_res tc_renamev(tc_file_pair *pairs, int count, bool is_transaction)
{
	return posix_renamev(pairs, count, is_transaction);
}

tc_res tc_removev(tc_file *files, int count, bool is_transaction)
{
	if (TC_IMPL_IS_NFS4) {
		return nfs4_removev(files, count, is_transaction);
	} else {
		return posix_removev(files, count, is_transaction);
	}
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

tc_res tc_ensure_dir(const char *dir, mode_t mode, slice_t *leaf)
{
	tc_res tcres = TC_OKAY;
	slice_t *comps;
	struct tc_attrs *dirs;
	buf_t *path;
	int i;
	int n;
	int absent;
	bool is_absolute = dir && dir[0] == '/';

	n = tc_path_tokenize(dir, &comps);
	if (n < 0) {
		return tc_failure(0, -n);
	}

	if (leaf && n > 0) {
		*leaf = comps[--n];
	}

	if (n == 0) {
		goto exit;
	}

	dirs = alloca(n * sizeof(*dirs));
	for (i = 0; i < n; ++i) {
		dirs[i].file = tc_file_from_path(new_auto_str(comps[i]));
	}

	tcres = tc_getattrsv(dirs, n, false);
	if (tcres.okay || tcres.err_no != ENOENT) {
		goto exit;
	}

	path = new_auto_buf(strlen(dir) + 1);
	absent = 0;
	for (i = 0; i < n; ++i) {
		if (i < tcres.index) {
			tc_path_append(path, comps[i]);
			continue;
		} else if (i == tcres.index) {
			tc_path_append(path, comps[i]);
			tc_set_up_creation(&dirs[absent], asstr(path), mode);
		} else {
			tc_set_up_creation(&dirs[absent],
					   new_auto_str(comps[i]), mode);
		}
		++absent;
	}

	if (absent == 0)
		goto exit;

	tcres = tc_mkdirv(dirs, absent, false);
	for (i = 0; i < absent; ++i) {
		if (tcres.okay || i < tcres.index) {
			assert(dirs[i].file.type == TC_FILE_HANDLE);
			free((void *)dirs[i].file.handle);
		}
	}

exit:
	free(comps);
	return tcres;
}

tc_res tc_copyv(struct tc_extent_pair *pairs, int count, bool is_transaction)
{
	return TC_OKAY;
}

tc_res tc_write_adb(struct tc_adb *patterns, int count, bool is_transaction)
{
	return TC_OKAY;
}
