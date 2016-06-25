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
#include <stdio.h>
#include "tc_api.h"
#include "posix/tc_impl_posix.h"
#include "nfs4/tc_impl_nfs4.h"
#include "path_utils.h"
#include "common_types.h"
#include "sys/stat.h"
#include "tc_helper.h"

static tc_res TC_OKAY = { .index = -1, .err_no = 0, };

static bool TC_IMPL_IS_NFS4 = false;

static pthread_t tc_counter_thread;
static const char *tc_counter_path = "/tmp/tc-counters.txt";
static int tc_counter_running = 1;

const struct tc_attrs_masks TC_ATTRS_MASK_ALL = TC_MASK_INIT_ALL;
const struct tc_attrs_masks TC_ATTRS_MASK_NONE = TC_MASK_INIT_NONE;

bool tc_counter_printer(struct tc_func_counter *tfc, void *arg)
{
	buf_t *pbuf = (buf_t *)arg;
	buf_appendf(pbuf, "%s %u %u %llu %llu ",
		    tfc->name,
		    __sync_fetch_and_or(&tfc->calls, 0),
		    __sync_fetch_and_or(&tfc->failures, 0),
		    __sync_fetch_and_or(&tfc->micro_ops, 0),
		    __sync_fetch_and_or(&tfc->time_ns, 0));
	return true;
}

static void *output_tc_counters(void *arg)
{
	char buf[4096];
	buf_t bf = BUF_INITIALIZER(buf, 4096);

	FILE *pfile = fopen(tc_counter_path, "w");
	while (__sync_fetch_and_or(&tc_counter_running, 0)) {
		buf_reset(&bf);
		tc_iterate_counters(tc_counter_printer, &bf);
		buf_append_char(&bf, '\n');
		fwrite(bf.data, 1, bf.size, pfile);
		fflush(pfile);
		sleep(TC_COUNTER_OUTPUT_INTERVAL);
	}
	fclose(pfile);
	return NULL;
}

/* Not thread-safe */
void *tc_init(const char *config_path, const char *log_path, uint16_t export_id)
{
	void *context;
	int retval;

	TC_IMPL_IS_NFS4 = (config_path !=  NULL);
	if (TC_IMPL_IS_NFS4) {
		context = nfs4_init(config_path, log_path, export_id);
	} else {
		context = posix_init(config_path, log_path);
	}

	if (!context) {
		return NULL;
	}

	tc_counter_running = 1;
	retval =
	    pthread_create(&tc_counter_thread, NULL, &output_tc_counters, NULL);
	if (retval != 0) {
		fprintf(stderr, "failed to create tc_counter thread: %s\n",
			strerror(retval));
		tc_deinit(context);
		return NULL;
	}

	return context;
}

void tc_deinit(void *module)
{
	__sync_fetch_and_sub(&tc_counter_running, 1);
	if (TC_IMPL_IS_NFS4) {
		nfs4_deinit(module);
	}
}

tc_file *tc_openv(const char **paths, int count, int *flags, mode_t *modes)
{
	tc_file *tcfs;
	TC_DECLARE_COUNTER(open);

	TC_START_COUNTER(open);
	if (TC_IMPL_IS_NFS4) {
		tcfs = nfs4_openv(paths, count, flags, modes);
	} else {
		tcfs = posix_openv(paths, count, flags, modes);
	}
	TC_STOP_COUNTER(open, count, tcfs != NULL);

	return tcfs;
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
	tc_res tcres;
	TC_DECLARE_COUNTER(close);

	TC_START_COUNTER(close);
	if (TC_IMPL_IS_NFS4) {
		tcres = nfs4_closev(tcfs, count);
	} else {
		tcres = posix_closev(tcfs, count);
	}
	TC_STOP_COUNTER(close, count, tc_okay(tcres));

	return tcres;
}

off_t tc_fseek(tc_file *tcf, off_t offset, int whence)
{
	off_t res;
	TC_DECLARE_COUNTER(seek);

	TC_START_COUNTER(seek);
	if (TC_IMPL_IS_NFS4) {
		res = nfs4_fseek(tcf, offset, whence);
	} else {
		res = posix_fseek(tcf, offset, whence);
	}
	TC_STOP_COUNTER(seek, 1, res != -1);

	return res;
}

tc_file* tc_open_by_path(int dirfd, const char *pathname, int flags, mode_t mode)
{
	return tc_openv(&pathname, 1, &flags, &mode);
}

int tc_close(tc_file *tcf)
{
	return tc_closev(tcf, 1).err_no;
}

tc_res tc_readv(struct tc_iovec *reads, int count, bool is_transaction)
{
	int i;
	tc_res tcres;
	TC_DECLARE_COUNTER(read);

	TC_START_COUNTER(read);
	for (i = 0; i < count; ++i) {
		if (reads[i].is_creation) {
			TC_STOP_COUNTER(read, count, false);
			return tc_failure(i, EINVAL);
		}
	}
	/**
	 * TODO: check if the functions should use posix or TC depending on the
	 * back-end file system.
	 */
	if (TC_IMPL_IS_NFS4) {
		tcres = nfs4_readv(reads, count, is_transaction);
	} else {
		tcres = posix_readv(reads, count, is_transaction);
	}
	TC_STOP_COUNTER(read, count, tc_okay(tcres));

	return tcres;
}

tc_res tc_writev(struct tc_iovec *writes, int count, bool is_transaction)
{
	tc_res tcres;
	TC_DECLARE_COUNTER(write);

	TC_START_COUNTER(write);
	if (TC_IMPL_IS_NFS4) {
		tcres = nfs4_writev(writes, count, is_transaction);
	} else {
		tcres = posix_writev(writes, count, is_transaction);
	}
	TC_STOP_COUNTER(write, count, tc_okay(tcres));

	return tcres;
}

tc_res tc_getattrsv(struct tc_attrs *attrs, int count, bool is_transaction)
{
	tc_res res;
	char *paths[count];
	int original_indices[count];

	char **bufs = alloca(sizeof(char*) * count);
	size_t *bufsizes = alloca(sizeof(size_t) * count);

	int link_count = 0;

	res = tc_lgetattrsv(attrs, count, false);
	if (!tc_okay(res)) {
		return res;
	}

	for (int i = 0; i < count; i++) {
		if (attrs[i].mode & S_IFMT == S_IFLNK) {
			tc_file file = attrs[i].file;
			assert(file.type == TC_FILE_PATH);
			if (file.fd == TC_FD_ABS) {
				paths[link_count] = file.path;
			} else if (file.fd == TC_FD_CWD) {
				char *path = alloca(sizeof(char) * PATH_MAX);
				tc_path_join(tc_getcwd(), file.path, path, PATH_MAX);
				paths[link_count] = path;
			}
			bufs[link_count] = alloca(sizeof(char) * PATH_MAX);
			bufsizes[link_count] = PATH_MAX;

			//Save original index into attrs so we can overwrite this data
			//with the attrs of what the link points to later
			original_indices[link_count] = i;

			link_count++;	
		}
	}
	
	//if nothing was a symlink, then our prior call to tc_lgetattrsv() sufficed, so we're done
	if (link_count == 0) {
		return res;
	}

	
	res = tc_readlinkv((const char**) paths, bufs, bufsizes, link_count, false);
	if (!tc_okay(res)) {
		return res;
	}

	//Cannot be moved to top of function
	//since it relies on link_count being the proper length
	struct tc_attrs linked_attrs[link_count];

	for (int i = 0; i < link_count; i++) {
		linked_attrs[i].file = tc_file_from_path(bufs[i]);
	}
	
	res = tc_lgetattrsv(linked_attrs, link_count, is_transaction);
	if (!tc_okay(res)) {
		res.index = original_indices[res.index];
		return res;
	}
	
	for (int i = 0; i < link_count; i++) {
		attrs[original_indices[i]] = linked_attrs[i];
	}

	return res;
}

tc_res tc_lgetattrsv(struct tc_attrs *attrs, int count, bool is_transaction)
{
	tc_res tcres;
	TC_DECLARE_COUNTER(lgetattrs);

	TC_START_COUNTER(lgetattrs);
	if (TC_IMPL_IS_NFS4) {
		tcres = nfs4_lgetattrsv(attrs, count, is_transaction);
	} else {
		tcres = posix_lgetattrsv(attrs, count, is_transaction);
	}
	TC_STOP_COUNTER(lgetattrs, count, tc_okay(tcres));

	return tcres;
}

static int tc_stat_impl(tc_file tcf, struct stat *buf, bool readlink)
{
	const char *path;
	char *linkbuf;
	char *link_target;
	int ret;
	tc_res tcres;
	struct tc_attrs tca = {
		.file = tcf,
		.masks = TC_ATTRS_MASK_ALL,
	};

	tcres = tc_getattrsv(&tca, 1, false);
	if (!tc_okay(tcres)) {
		return tcres.err_no;
	}

	if (!readlink || !S_ISLNK(tca.mode)) {
		tc_attrs2stat(&tca, buf);
		return 0;
	}

	assert(tcf.type == TC_FILE_PATH);

	linkbuf = alloca(PATH_MAX);
	link_target = alloca(PATH_MAX);

	while (S_ISLNK(tca.mode)) {
		path = tca.file.path;
		ret = tc_readlink(path, linkbuf, PATH_MAX);
		if (ret != 0) {
			return ret;
		}

		tc_path_joinall(link_target, PATH_MAX, path, "..", linkbuf);

		tca.file.path = link_target;
		tcres = tc_getattrsv(&tca, 1, false);
		if (!tc_okay(tcres)) {
			return tcres.err_no;
		}
	}

	tc_attrs2stat(&tca, buf);
	return 0;
}

int tc_stat(const char *path, struct stat *buf)
{
	return tc_stat_impl(tc_file_from_path(path), buf, true);
}

int tc_fstat(tc_file *tcf, struct stat *buf)
{
	return tc_stat_impl(*tcf, buf, false);
}

int tc_lstat(const char *path, struct stat *buf)
{
	return tc_stat_impl(tc_file_from_path(path), buf, false);
}

tc_res tc_setattrsv(struct tc_attrs *attrs, int count, bool is_transaction)
{
	tc_res tcres;
	TC_DECLARE_COUNTER(setattrs);

	TC_START_COUNTER(setattrs);
	if (TC_IMPL_IS_NFS4) {
		tcres = nfs4_setattrsv(attrs, count, is_transaction);
	} else {
		tcres = posix_setattrsv(attrs, count, is_transaction);
	}
	TC_STOP_COUNTER(setattrs, count, tc_okay(tcres));

	return tcres;
}

struct _tc_attrs_array {
	struct tc_attrs *attrs;
	size_t size;
	size_t capacity;
};

static bool fill_dir_entries(const struct tc_attrs *entry, const char *dir,
			     void *cbarg)
{
	void *buf;
	struct _tc_attrs_array *parray = (struct _tc_attrs_array *)cbarg;

	if (parray->size >= parray->capacity) {
		buf = realloc(parray->attrs,
			      sizeof(struct tc_attrs) * parray->capacity * 2);
		if (!buf) {
			return false;
		}
		parray->attrs = (struct tc_attrs *)buf;
		parray->capacity *= 2;
	}
	parray->attrs[parray->size] = *entry;
	parray->attrs[parray->size].file.path = strdup(entry->file.path);
	parray->size += 1;

	return true;
}

tc_res tc_listdir(const char *dir, struct tc_attrs_masks masks, int max_count,
		  bool recursive, struct tc_attrs **contents, int *count)
{
	tc_res tcres;
	struct _tc_attrs_array atarray;

	atarray.size = 0;
	if (max_count == 0) {
		atarray.capacity = 8;
	} else {
		assert(max_count > 0);
		atarray.capacity = max_count;
	}
	atarray.attrs = calloc(atarray.capacity, sizeof(struct tc_attrs));
	if (!atarray.attrs) {
		return tc_failure(0, ENOMEM);
	}

	tcres = tc_listdirv(&dir, 1, masks, max_count, recursive,
			    fill_dir_entries, &atarray, false);
	if (!tc_okay(tcres)) {
		tc_free_attrs(atarray.attrs, atarray.size, true);
	}

	*count = atarray.size;
	if (*count == 0) {
		free(atarray.attrs);
		*contents = NULL;
	} else {
		*contents = atarray.attrs;
	}

	return tcres;
}

tc_res tc_listdirv(const char **dirs, int count, struct tc_attrs_masks masks,
		   int max_entries, bool recursive, tc_listdirv_cb cb,
		   void *cbarg, bool is_transaction)
{
	tc_res tcres;
	TC_DECLARE_COUNTER(listdir);

	TC_START_COUNTER(listdir);
	if (TC_IMPL_IS_NFS4) {
		tcres = nfs4_listdirv(dirs, count, masks, max_entries, recursive,
				     cb, cbarg, is_transaction);
	} else {
		tcres = posix_listdirv(dirs, count, masks, max_entries,
				      recursive, cb, cbarg, is_transaction);
	}
	TC_STOP_COUNTER(listdir, count, tc_okay(tcres));

	return tcres;
}

tc_res tc_renamev(tc_file_pair *pairs, int count, bool is_transaction)
{
	tc_res tcres;
	TC_DECLARE_COUNTER(rename);

	TC_START_COUNTER(rename);
	if (TC_IMPL_IS_NFS4) {
		tcres = nfs4_renamev(pairs, count, is_transaction);
	} else {
		tcres = posix_renamev(pairs, count, is_transaction);
	}
	TC_STOP_COUNTER(rename, count, tc_okay(tcres));

	return tcres;
}

tc_res tc_removev(tc_file *files, int count, bool is_transaction)
{
	tc_res tcres;
	TC_DECLARE_COUNTER(remove);

	TC_START_COUNTER(remove);
	if (TC_IMPL_IS_NFS4) {
		tcres = nfs4_removev(files, count, is_transaction);
	} else {
		tcres = posix_removev(files, count, is_transaction);
	}
	TC_STOP_COUNTER(remove, count, tc_okay(tcres));

	return tcres;
}

int tc_unlink(const char *path)
{
	tc_file tcf = tc_file_from_path(path);
	return tc_removev(&tcf, 1, false).err_no;
}

tc_res tc_unlinkv(const char **paths, int count)
{
	int i = 0, r = 0;
	tc_file *files;

	files = (tc_file *)alloca(count * sizeof(tc_file));
	for (i = 0; i < count; ++i) {
		files[i] = tc_file_from_path(paths[i]);
	}

	return tc_removev(files, count, false);
}

tc_res tc_mkdirv(struct tc_attrs *dirs, int count, bool is_transaction)
{
	int i;
	tc_res tcres;
	TC_DECLARE_COUNTER(mkdir);

	TC_START_COUNTER(mkdir);
	for (i = 0; i < count; ++i) {
		assert(dirs[i].masks.has_mode);
	}
	if (TC_IMPL_IS_NFS4) {
		tcres = nfs4_mkdirv(dirs, count, is_transaction);
	} else {
		tcres = posix_mkdirv(dirs, count, is_transaction);
	}
	TC_STOP_COUNTER(mkdir, count, tc_okay(tcres));

	return tcres;
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
		tcres = posix_lgetattrsv(&attrs, 1, false);
		if (tc_okay(tcres)) {
			continue;
		}
		if (tcres.err_no != ENOENT) {
			/*POSIX_ERR("failed to stat %s", path->data);*/
			return tcres;
		}
		tc_set_up_creation(&attrs, path->data, mode);
		tcres = posix_mkdirv(&attrs, 1, false);
		if (!tc_okay(tcres)) {
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
	if (tc_okay(tcres) || tcres.err_no != ENOENT) {
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
	tc_res tcres;
	TC_DECLARE_COUNTER(copy);

	TC_START_COUNTER(copy);
	if (TC_IMPL_IS_NFS4) {
		tcres = nfs4_copyv(pairs, count, is_transaction);
	} else {
		tcres = posix_copyv(pairs, count, is_transaction);
	}
	TC_STOP_COUNTER(copy, count, tc_okay(tcres));

	return tcres;
}

tc_res tc_symlinkv(const char **oldpaths, const char **newpaths, int count,
		   bool istxn)
{
	tc_res tcres;
	TC_DECLARE_COUNTER(symlink);

	TC_START_COUNTER(symlink);
	if (TC_IMPL_IS_NFS4) {
		tcres = nfs4_symlinkv(oldpaths, newpaths, count, istxn);
	} else {
		tcres = posix_symlinkv(oldpaths, newpaths, count, istxn);
	}
	TC_STOP_COUNTER(symlink, count, tc_okay(tcres));

	return tcres;
}

tc_res tc_readlinkv(const char **paths, char **bufs, size_t *bufsizes,
		    int count, bool istxn)
{
	tc_res tcres;
	TC_DECLARE_COUNTER(readlink);

	TC_START_COUNTER(readlink);
	if (TC_IMPL_IS_NFS4) {
		tcres = nfs4_readlinkv(paths, bufs, bufsizes, count, istxn);
	} else {
		tcres = posix_readlinkv(paths, bufs, bufsizes, count, istxn);
	}
	TC_STOP_COUNTER(readlink, count, tc_okay(tcres));

	return tcres;
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
