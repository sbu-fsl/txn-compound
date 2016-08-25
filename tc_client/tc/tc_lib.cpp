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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tc_api.h"
#include "tc_helper.h"
#include "path_utils.h"

#include <algorithm>
#include <queue>
#include <vector>

using std::vector;
using std::queue;

struct rm_cb_args {
	vector<const char *> *dirs;
	vector<const char *> *files;
};

struct cp_cb_args {
	vector<const char *> *dirs;
	vector<const char *> *files;
	vector<const char *> *symlinks;
};

static bool rm_list_callback(const struct tc_attrs *entry, const char *dir,
			     void *cbarg)
{
	struct rm_cb_args *args = (struct rm_cb_args *)cbarg;
	if (S_ISDIR(entry->mode)) {
		args->dirs->push_back(strdup(entry->file.path));
	} else {
		args->files->push_back(strdup(entry->file.path));
	}
	return true;
}

static void free_paths(vector<const char *> *paths)
{
	for (const char *p : *paths) {
		free((char *)p);
	}
	paths->clear();
}

static bool cp_list_callback(const struct tc_attrs *entry, const char *dir,
			     void *cbarg)
{
	struct cp_cb_args *args = (struct cp_cb_args *)cbarg;
	if (S_ISDIR(entry->mode)) {
		args->dirs->push_back(strdup(entry->file.path));
	} else if (S_ISLNK(entry->mode)) {
		args->symlinks->push_back(strdup(entry->file.path));
	} else {
		args->files->push_back(strdup(entry->file.path));
	}
	return true;
}

static char *new_cp_target_path(const char *src_obj, const char *src_dir,
				const char *dst_dir)
{
	char *path = (char*) malloc(PATH_MAX);
	const char *p = src_obj;
	for (int j = 0; *p != '\0' && *p == src_dir[j]; j++)
		++p;
	tc_path_join(dst_dir, p, path, PATH_MAX);
	return path;
}

static tc_res tc_cp_mkdirs(const char *src_dir, const char **dirs, int count,
			   const char *dst_dir)
{
	struct tc_attrs attrs[count];
	for (int i = 0; i < count; i++) {
		attrs[i].file = tc_file_from_path(
		    new_cp_target_path(dirs[i], src_dir, dst_dir));
		attrs[i].masks = TC_ATTRS_MASK_NONE;
		attrs[i].masks.has_mode = true;
		attrs[i].mode = 0755;
	}
	tc_res res = tc_mkdirv(attrs, count, false);
	if (!tc_okay(res)) {
		printf("mkdirv-failed: %s (%d-th %s)\n", strerror(res.err_no),
		       res.index, attrs[res.index].file.path);
	}

	for (int i = 0; i < count; i++) {
		free((char*)attrs[i].file.path);
	}

	return res;
}

static tc_res tc_cp_files(const char *src_dir, const char **srcs, int count,
			  const char *dst_dir, bool symlink)
{
	tc_res res;
	struct tc_extent_pair *pairs;
	const char **dst_paths;

	if (symlink) {
		dst_paths = (const char **) malloc(sizeof(char*) * count);
	} else {
		pairs = (struct tc_extent_pair *)malloc(
		    sizeof(struct tc_extent_pair) * count);
	}

	for (int i = 0; i < count; i++) {
		char *path = new_cp_target_path(srcs[i], src_dir, dst_dir);
		if (symlink) {
			dst_paths[i] = path;
		} else {
			pairs[i].src_path = srcs[i];
			pairs[i].dst_path = path;
			pairs[i].src_offset = 0;
			pairs[i].dst_offset = 0;
			pairs[i].length = 0;
		}
	}
	if (symlink) {
		res = tc_symlinkv(srcs, dst_paths, count, false);
		if (!tc_okay(res)) {
			printf("tc_symlinkv: %s (%s -> %s)\n",
			       strerror(res.err_no), srcs[res.index],
			       dst_paths[res.index]);
		}
		for (int i = 0; i < count; i++) {
			free((char*) dst_paths[i]);
		}
		free((const char **) dst_paths);
	} else {
		res = tc_lcopyv(pairs, count, false);
		if (!tc_okay(res)) {
			printf("tc_lcopyv: %s (%s)\n", strerror(res.err_no),
			       pairs[res.index].src_path);
		}
		for (int i = 0; i < count; i++) {
			free((char*) pairs[i].dst_path);
		}
		free((struct tc_extent_pair*) pairs);
	}
	return res;
}

tc_res tc_cp_symlinks(vector<const char *> *links, const char *src_dir,
		      const char *dst_dir)
{
	size_t count = links->size();
	char *linkbufs;
	vector<char *> bufs(count);
	vector<size_t> bufsizes(count, PATH_MAX);

	linkbufs = (char *)malloc(count * PATH_MAX);
	for (size_t i = 0; i < count; ++i) {
		bufs[i] = linkbufs + i * PATH_MAX;
	}
	tc_res tcres = tc_readlinkv(links->data(), bufs.data(), bufsizes.data(),
				    count, false);
	if (!tc_okay(tcres)) {
		fprintf(stderr, "tc_readlinkv failed: %s at %d (%s)\n",
			tcres.index, strerror(tcres.err_no),
			(*links)[tcres.index]);
		free(linkbufs);
		return tcres;
	}

	vector<const char *> newlinks(count);
	for (size_t i = 0; i < count; ++i) {
		newlinks[i] = new_cp_target_path((*links)[i], src_dir, dst_dir);
	}
	tcres = tc_symlinkv((const char **)bufs.data(), newlinks.data(), count,
			    false);
	if (!tc_okay(tcres)) {
		fprintf(stderr, "tc_readlinkv failed: %s at %d (%s)\n",
			tcres.index, strerror(tcres.err_no),
			(*links)[tcres.index]);
	}

	free(linkbufs);
	free_paths(&newlinks);
	return tcres;
}

tc_res tc_cp_recursive(const char *src_dir, const char *dst, bool symlink)
{
	vector<const char *> dirs;
	vector<const char *> files_to_copy;
	vector<const char *> symlinks;
	struct tc_attrs_masks listdir_mask = TC_ATTRS_MASK_NONE;
	listdir_mask.has_mode = true;
	struct cp_cb_args cbargs;
	tc_res tcres = {0};
	cbargs.dirs = &dirs;
	cbargs.files = &files_to_copy;
	cbargs.symlinks = &symlinks;

	dirs.push_back(strdup(src_dir));

	int created = 0;  // index to directories created so far
	while (created < dirs.size() || !files_to_copy.empty()) {
		int n = dirs.size() - created;
		tcres = tc_listdirv(dirs.data() + created, n, listdir_mask, 0,
				    false, cp_list_callback, &cbargs, false);
		if (!tc_okay(tcres)) {
			break;
		}

		tcres = tc_cp_mkdirs(src_dir, dirs.data() + created, n, dst);
		if (!tc_okay(tcres)) {
			break;
		}
		created += n;

		tcres = tc_cp_files(src_dir, files_to_copy.data(),
				    files_to_copy.size(), dst, symlink);
		free_paths(&files_to_copy);
		if (!tc_okay(tcres)) {
			break;
		}
	}

	if (tc_okay(tcres)) {
		tcres = tc_cp_symlinks(&symlinks, src_dir, dst);
	}

	free_paths(&dirs);
	free_paths(&files_to_copy);
	free_paths(&symlinks);

	return tcres;
}

// TODO: handle when "recursive" is false
tc_res tc_rm(const char **objs, int count, bool recursive)
{
	vector<const char *> dirs;
	vector<const char *> files_to_remove;
	struct tc_attrs_masks listdir_mask;
	listdir_mask.has_mode = true;
	listdir_mask.has_nlink = true;
	struct rm_cb_args cbargs;
	cbargs.dirs = &dirs;
	cbargs.files = &files_to_remove;

	// initialize "dirs"
	{
		vector<struct tc_attrs> attrs(count);
		for (int i = 0; i < count; ++i) {
			attrs[i].file = tc_file_from_path(objs[i]);
			attrs[i].masks = TC_ATTRS_MASK_NONE;
			attrs[i].masks.has_mode = true;
		}

		for (int i = 0; i < attrs.size(); ) {
			tc_res tcres = tc_getattrsv(attrs.data() + i,
						    attrs.size() - i, false);
			if (tc_okay(tcres)) {
				break;
			} else if (tcres.err_no == ENOENT) {
				// ignore not existed entries
				attrs.erase(attrs.begin() + (i + tcres.index));
				i += tcres.index - 1;
			} else {
				return tcres;
			}
		}

		for (int i = 0; i < attrs.size(); ++i) {
			if (S_ISDIR(attrs[i].mode)) {
				dirs.push_back(strdup(objs[i]));
			} else {
				files_to_remove.push_back(strdup(objs[i]));
			}
		}
	}

	int emptied = 0;  // index to directories emptied so far
	while (emptied < dirs.size() || !files_to_remove.empty()) {
		tc_res tcres =
		    tc_unlinkv(files_to_remove.data(), files_to_remove.size());
		if (!tc_okay(tcres)) {
			return tcres;
		}

		free_paths(&files_to_remove);

		int n = dirs.size() - emptied;
		tcres = tc_listdirv(dirs.data() + emptied, n, listdir_mask, 0,
				    false, rm_list_callback, &cbargs, false);
		if (!tc_okay(tcres)) {
			return tcres;
		}

		emptied += n;
	}

	while (!dirs.empty()) {
		vector<const char*> dirs_to_remove(dirs.rbegin(), dirs.rend());
		tc_res tcres = tc_unlinkv(dirs_to_remove.data(), dirs.size());
		if (!tc_okay(tcres)) {
			return tcres;
		}

		free_paths(&dirs);
	}

	return tc_failure(0, 0);
}
