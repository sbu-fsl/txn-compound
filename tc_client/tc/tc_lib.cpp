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

#include <algorithm>
#include <queue>
#include <vector>

using std::vector;
using std::queue;

struct rm_cb_args {
	vector<const char *> *dirs;
	vector<const char *> *files;
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

static void free_paths(vector<const char *> *paths, bool empty = true)
{
	for (const char *p : *paths) {
		free((char *)p);
	}
	if (empty) paths->clear();
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

		tc_res tcres = tc_getattrsv(attrs.data(), count, false);
		if (!tc_okay(tcres)) {
			return tcres;
		}

		for (int i = 0; i < count; ++i) {
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

		const int LISTDIR_LIMIT = 8;
		int n = std::min<int>(LISTDIR_LIMIT, dirs.size() - emptied);
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
