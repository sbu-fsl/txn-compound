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
 * This is an example renaming multiple files in one RPC.
 * It has the same effect as the bash command:
 *
 *  $ ls /vfs0/rndir1
 *  a b c d e
 *  $ ls /vfs0/rndir2
 *  $ mv /vfs0/rndir1/{a,b,c,d,e} /vfs0/rndir2
 *  $ ls /vfs0/rndir2
 *  a b c d e
 *
 * @file tc_test_rename.c
 * @brief Test renaming multiple files.
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
#include <signal.h>		/* for sigaction */
#include <errno.h>
#include "../nfs4/nfs4_util.h"

static char exe_path[PATH_MAX];
static char tc_config_path[PATH_MAX];

#define DEFAULT_LOG_FILE "/tmp/tc_test_rename.log"

int main(int argc, char *argv[])
{
	void *context = NULL;
	const int N = 5;
	int i;
	tc_file_pair pairs[N];
	tc_res res;
	struct tc_iovec file_iov[N];
	const char *srcpaths[] = { "/vfs0/rndir1/a", "/vfs0/rndir1/b",
				   "/vfs0/rndir1/c", "/vfs0/rndir1/d",
				   "/vfs0/rndir1/e" };
	const char *dstpaths[] = { "/vfs0/rndir2/a", "/vfs0/rndir2/b",
				   "/vfs0/rndir2/c", "/vfs0/rndir2/d",
				   "/vfs0/rndir2/e" };
	slice_t tmp;

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

	res = tc_ensure_dir(srcpaths[0], 0755, &tmp);
	if (!res.okay) {
		NFS4_ERR("failed to create source directory %s",
			 srcpaths[0]);
		goto exit;
	}
	res = tc_ensure_dir(dstpaths[0], 0755, &tmp);
	if (!res.okay) {
		NFS4_ERR("failed to create destination directory %s",
			 srcpaths[0]);
		goto exit;
	}

	/* create files */
	for (i = 0; i < N; ++i) {
		file_iov[i].file = tc_file_from_path(srcpaths[i]);
		file_iov[i].is_creation = true;
		file_iov[i].offset = 0;
		/* The file content is its path */
		file_iov[i].length = strlen(srcpaths[i]);
		file_iov[i].data = (char *)srcpaths[i];
	}
	res = tc_writev(file_iov, N, false);
	if (!res.okay) {
		fprintf(stderr, "Failed to create test files\n");
		goto exit;
	}

	/* set up rename request */
	for (i = 0; i < N; ++i) {
		pairs[i].src_file = tc_file_from_path(srcpaths[i]);
		pairs[i].dst_file = tc_file_from_path(dstpaths[i]);
	}

	res = tc_renamev(pairs, N, false);
	if (res.okay) {
		fprintf(stderr, "Successfully renamed %d test files\n", N);
	} else {
		fprintf(stderr,
			"Failed to rename %d-th file (%s) with error code %d "
			"(%s). See log file at %s for details.\n",
			res.index, srcpaths[res.index], res.err_no,
			strerror(res.err_no), DEFAULT_LOG_FILE);
	}

exit:
	tc_deinit(context);

	return res.okay ? 0 : res.err_no;
}
