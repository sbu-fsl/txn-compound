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
#include <linux/limits.h>
#include <assert.h>
#include "tc_api.h"
#include "posix/tc_impl_posix.h"
#include "nfs4/tc_impl_nfs4.h"
#include "path_utils.h"
#include "common_types.h"

static tc_res TC_OKAY = { .okay = true, .index = -1, .err_no = 0, };

static bool TC_IMPL_IS_NFS4 = false;


const struct tc_attrs_masks TC_ATTRS_MASK_ALL = TC_MASK_INIT_ALL;
const struct tc_attrs_masks TC_ATTRS_MASK_NONE = TC_MASK_INIT_NONE;

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

tc_file *tc_openv(const char **paths, int count, int *flags, mode_t *modes)
{
	if (TC_IMPL_IS_NFS4) {
		return nfs4_openv(paths, count, flags, modes);
	} else {
		return posix_openv(paths, count, flags, modes);
	}
}

tc_file *tc_openv_simple(const char **paths, int count, int flags, mode_t mode)
{
	int i;
	int *flag_array = alloca(count * sizeof(int));
	mode_t *mode_array = alloca(count * sizeof(mode_t));
	for (i = 0; i < count; ++i) {
		flag_array[i] = flags;
		mode_array[i] = mode;
	}
	return tc_openv(paths, count, flag_array, mode_array);
}

tc_res tc_closev(tc_file *tcfs, int count)
{
	if (TC_IMPL_IS_NFS4) {
		return nfs4_closev(tcfs, count);
	} else {
		return posix_closev(tcfs, count);
	}
}

off_t tc_fseek(tc_file *tcf, off_t offset, int whence)
{
	if (TC_IMPL_IS_NFS4) {
		return nfs4_fseek(tcf, offset, whence);
	} else {
		return posix_fseek(tcf, offset, whence);
	}
}

tc_file* tc_open_by_path(int dirfd, const char *pathname, int flags, mode_t mode)
{
	return tc_openv(&pathname, 1, &flags, &mode);
}

int tc_close(tc_file *tcf)
{
	tc_res tcres = tc_closev(tcf, 1);
	return tcres.okay ? 0 : -tcres.err_no;
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
	if (TC_IMPL_IS_NFS4) {
		return nfs4_renamev(pairs, count, is_transaction);
	} else {
		return posix_renamev(pairs, count, is_transaction);
	}
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

static tc_res posix_ensure_dir(slice_t *comps, int n, mode_t mode)
{
	tc_res tcres = TC_OKAY;
	struct tc_attrs attrs;
	buf_t *path;
	int i;

	path = new_auto_buf(PATH_MAX + 1);
	for (i = 0; i < n; ++i) {
		tc_path_append(path, comps[i]);
		attrs.file = tc_file_from_path(asstr(path));
		tcres = posix_getattrsv(&attrs, 1, false);
		if (tcres.okay) {
			continue;
		}
		if (tcres.err_no != ENOENT) {
			/*POSIX_ERR("failed to stat %s", path->data);*/
			return tcres;
		}
		tc_set_up_creation(&attrs, path->data, mode);
		tcres = posix_mkdirv(&attrs, 1, false);
		if (!tcres.okay) {
			/*POSIX_ERR("failed to create %s", path->data);*/
			return tcres;
		}
	}

	return tcres;
}

static tc_res nfs4_ensure_dir(slice_t *comps, int n, mode_t mode)
{
	tc_res tcres = TC_OKAY;
	struct tc_attrs *dirs;
	buf_t *path;
	int absent;
	int i;

	dirs = alloca(n * sizeof(*dirs));
	dirs[0].file = tc_file_from_path(new_auto_str(comps[0]));
	for (i = 1; i < n; ++i) {
		dirs[i].file = tc_file_from_cfh(new_auto_str(comps[i]));
	}

	tcres = tc_getattrsv(dirs, n, false);
	if (tcres.okay || tcres.err_no != ENOENT) {
		return tcres;
	}

	path = new_auto_buf(PATH_MAX + 1);
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
			dirs[absent].file.type = TC_FILE_CURRENT;
		}
		++absent;
	}

	if (absent == 0)
		return tcres;

	tcres = tc_mkdirv(dirs, absent, false);
	for (i = 0; i < absent; ++i) {
		if (tcres.okay || i < tcres.index) {
			assert(dirs[i].file.type == TC_FILE_HANDLE);
			free((void *)dirs[i].file.handle);
		}
	}

	return tcres;
}

tc_res tc_ensure_dir(const char *dir, mode_t mode, slice_t *leaf)
{
	tc_res tcres = TC_OKAY;
	slice_t *comps;
	int n;

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

	if (TC_IMPL_IS_NFS4) {
		tcres = nfs4_ensure_dir(comps, n, mode);
	} else {
		tcres = posix_ensure_dir(comps, n, mode);
	}

exit:
	free(comps);
	return tcres;
}

tc_res tc_copyv(struct tc_extent_pair *pairs, int count, bool is_transaction)
{
	if (TC_IMPL_IS_NFS4) {
		return nfs4_copyv(pairs, count, is_transaction);
	} else {
		return posix_copyv(pairs, count, is_transaction);
	}
}

tc_res tc_write_adb(struct tc_adb *patterns, int count, bool is_transaction)
{
	return TC_OKAY;
}


int tc_chdir(const char *path)
{
	if (TC_IMPL_IS_NFS4) {
		return nfs4_chdir(path);
	} else {
		return posix_chdir(path);
	}
}

char *tc_getcwd()
{
	if (TC_IMPL_IS_NFS4) {
		return nfs4_getcwd();
	} else {
		return posix_getcwd();
	}
}
