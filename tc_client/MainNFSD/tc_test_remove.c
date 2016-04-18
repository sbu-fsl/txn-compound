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
 * This is an example removing multiple files in one RPC.
 * It has the same effect as the bash command:
 *
 *  $ rm /vfs0/rmdir/{a,b,c,d,e}
 *
 * @file tc_test_remove.c
 * @brief Test removing multiple files.
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

#define DEFAULT_LOG_FILE "/tmp/tc_test_remove.log"

#define TC_TEST_NFS_DIR "/vfs0/rmdir"

int main(int argc, char *argv[])
{
	void *context = NULL;
	const int N = 5;
	int i;
	tc_file files[N];
	struct tc_iovec file_iov[N];
	tc_res res;
	const char *data = "hello world";
	const char *file_paths[] = { "/vfs0/rmdir/a", "/vfs0/rmdir/b",
				     "/vfs0/rmdir/c", "/vfs0/rmdir/d",
				     "/vfs0/rmdir/e" };

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

	res = tc_ensure_dir(TC_TEST_NFS_DIR, 0755, NULL);
	if (!res.okay) {
		NFS4_ERR("failed to create parent directory %s",
			 TC_TEST_NFS_DIR);
		goto exit;
	}

	/* Setup I/O request */
	for (i = 0; i < N; ++i) {
		files[i] = tc_file_from_path(file_paths[i]);
		file_iov[i].file = files[i];
		file_iov[i].is_creation = true;
		file_iov[i].offset = 0;
		/* The file content is its path */
		file_iov[i].length = strlen(file_paths[i]);
		file_iov[i].data = (char *)file_paths[i];
	}

	/* Write the file using NFS compounds; nfs4_writev() will open the file
	 * with CREATION flag, write to it, and then close it. */
	res = tc_writev(file_iov, N, false);
	if (res.okay) {
		fprintf(stderr, "Successfully created %d test files\n", N);
	} else {
		fprintf(stderr, "Failed to create test files\n");
		goto exit;
	}

	res = tc_removev(files, N, false);
	if (res.okay) {
		fprintf(stderr, "Successfully removed %d test files\n", N);
	} else {
		fprintf(stderr,
			"Failed to remove %d-th file with error code %d "
			"(%s). See log file at %s for details.\n",
			res.index, res.err_no, strerror(res.err_no),
			DEFAULT_LOG_FILE);
	}

exit:
	tc_deinit(context);

	return res.okay ? 0 : res.err_no;
}
