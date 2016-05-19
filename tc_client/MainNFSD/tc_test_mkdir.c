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

/**
 * This is an example showing how to create a deep directory with only two NFS
 * RPCs using the TC API (see tc_client/include/tc_api.h).
 *
 * It has the same effect as bash command "mkdir -p /vfs0/a/b/c/d/e". The TC
 * API has a helper function that has the same effects: tc_ensure_dir().
 *
 * @file tc_test_mkdir.c
 * @brief Test creating a deep directoriy and all its ancestory directories.
 *
 */
#include "config.h"
#include "nfs_init.h"
#include "fsal.h"
#include "log.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include "../nfs4/nfs4_util.h"
#include "common_types.h"

static char exe_path[PATH_MAX];
static char tc_config_path[PATH_MAX];

#define DEFAULT_LOG_FILE "/tmp/tc_test_mkdir.log"

int main(int argc, char *argv[])
{
	void *context = NULL;
	const int N = 6;
	struct tc_attrs dirs[N];
	slice_t *comps;
	tc_res res;
	int i;
	int n;
	const char *DIR_LEAF = "/vfs0/a/b/c/d/e";
	const char *DIR_PATHS[] = { "/vfs0", "a", "b", "c", "d", "e" };
	char prefix[PATH_MAX];

	/* Locate and use the default config file in the repo.  Before running
	 * this example, please update the config file to a correct NFS server.
	 */
	readlink("/proc/self/exe", exe_path, PATH_MAX);
	snprintf(tc_config_path, PATH_MAX,
		 "%s/../../../config/tc.ganesha.conf", dirname(exe_path));
	fprintf(stderr, "using config file: %s\n", tc_config_path);

	/* Initialize TC services and daemons */
	context = tc_init(tc_config_path, DEFAULT_LOG_FILE, 77);
	if (context == NULL) {
		NFS4_ERR("Error while initializing tc_client using config "
			 "file: %s; see log at %s",
			 tc_config_path, DEFAULT_LOG_FILE);
		return EIO;
	}

	/* Setup getattrs */
	dirs[0].file = tc_file_from_path(DIR_PATHS[0]);
	for (i = 1; i < N; ++i) {
		dirs[i].file = tc_file_from_cfh(DIR_PATHS[i]);
		memset(&dirs[i].masks, 0, sizeof(dirs[i].masks));
	}

	res = tc_getattrsv(dirs, N, false);
	if (tc_okay(res)) {
		fprintf(stderr, "directory %s already exists\n", DIR_LEAF);
		goto exit;
	} else {
		fprintf(stderr, "getattrsv failed at %d for file: %s (%d)\n",
			res.index, DIR_PATHS[res.index], res.err_no);
	}

	/* Setup mkdirv */
	prefix[0] = 0;
	n = 0;
	for (i = 0; i < N; ++i) {
		if (i < res.index) {
			tc_path_join(prefix, DIR_PATHS[i], prefix, PATH_MAX);
			continue;
		} else if (i == res.index) {
			tc_path_join(prefix, DIR_PATHS[i], prefix, PATH_MAX);
			tc_set_up_creation(&dirs[n], prefix, 0755);
		} else {
			tc_set_up_creation(&dirs[n], DIR_PATHS[i], 0755);
			dirs[n].file.type = TC_FILE_CURRENT;
		}
		fprintf(stderr, "prepare mkdir %s\n", dirs[n].file.path);
		++n;
	}
	assert(n == N - res.index);

	res = tc_mkdirv(dirs, n, false);

	/* Check results. */
	if (tc_okay(res)) {
		fprintf(stderr, "directory %s successfully created via NFS.\n",
			DIR_LEAF);
	} else {
		fprintf(stderr, "failed to create directory via NFS.\n");
	}

exit:
	tc_deinit(context);

	return res.err_no;
}
