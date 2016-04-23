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
 * This is an example showing how to create multiple sub-directories within one
 * directory.  It has the same effect as bash command
 *
 *	mkdir /vfs0/dirs/{a,b,c,d,e}
 *
 * TC achieves this using only one RPC (see tc_client/include/tc_api.h).
 *
 * @file tc_test_mkdirs.c
 * @brief Test creating multiple sub-directories.
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

#define DEFAULT_LOG_FILE "/tmp/tc_test_mkdirs.log"

int main(int argc, char *argv[])
{
	void *context = NULL;
	const int N = 5;
	struct tc_attrs dirs[N];
	char *path;
	tc_res res;
	int i;
	int rc;
	slice_t leaf;
	const char *DIR_PATHS[] = { "/vfs0/dirs/a", "/vfs0/dirs/b",
				    "/vfs0/dirs/c", "/vfs0/dirs/d",
				    "/vfs0/dirs/e" };

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

	/* create common parent directory */
	res = tc_ensure_dir(DIR_PATHS[0], 0755, &leaf);
	if (!res.okay) {
		NFS4_ERR("failed to create parent directory of %s",
			 DIR_PATHS[0]);
		goto exit;
	}

	/* set up sub-directories to create*/
	tc_set_up_creation(&dirs[0], DIR_PATHS[0], 0755);
	for (i = 1; i < N; ++i) {
		path = alloca(PATH_MAX);
		rc = tc_path_rebase(DIR_PATHS[0], DIR_PATHS[i], path, PATH_MAX);
		if (rc < 0) {
			fprintf(stderr, "failed to rebase %s to %s\n",
				DIR_PATHS[i], DIR_PATHS[0]);
			res = tc_failure(0, EINVAL);
			goto exit;
		}
		tc_set_up_creation(&dirs[i], path, 0755);
		dirs[i].file.type = TC_FILE_CURRENT;
	}

	res = tc_mkdirv(dirs, N, false);

	/* Check results. */
	if (res.okay) {
		fprintf(stderr,
			"All directories successfully created via NFS.\n");
	} else {
		fprintf(stderr, "Failed to create directories via NFS.\n");
	}

exit:
	tc_deinit(context);

	return res.okay ? 0 : res.err_no;
}
