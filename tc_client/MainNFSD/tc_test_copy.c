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
 * This is an example of coping files using NFSv4.2 server-side copy.
 * It has the same effect as the bash command:
 *
 *  $ echo /vfs0/srcdir/file-*.txt > /vfs0/dstdir
 *
 * @file tc_test_copy.c
 * @brief Test copying files.
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

#define DEFAULT_LOG_FILE "/tmp/tc_test_copy.log"

#define TC_TEST_NFS_FILE "/vfs0/hello.txt"

int main(int argc, char *argv[])
{
	void *context = NULL;
	struct tc_extent_pair pairs[2];
	struct tc_iovec iov[4];
	tc_res res;
	const char *data = "hello world";
	const char *srcdir = "/vfs0/srcdir";
	const char *dstdir = "/vfs0/dstdir";
	const char *fname1 = "file-1.txt";
	const char *fname2 = "file-2.txt";
	buf_t *pbuf;

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

	res = tc_ensure_dir(srcdir, 0755, NULL);
	if (!res.okay) {
		NFS4_ERR("failed to ensure source directory %s: %s",
			 srcdir, strerror(res.err_no));
		return res.err_no;
	}

	res = tc_ensure_dir(dstdir, 0755, NULL);
	if (!res.okay) {
		NFS4_ERR("failed to ensure source directory %s: %s",
			 dstdir, strerror(res.err_no));
		return res.err_no;
	}

	/* Setup I/O request */
	pbuf = new_auto_buf(PATH_MAX);
	tc_path_join_s(toslice(srcdir), toslice(fname1), pbuf);
	iov[0].file = tc_file_from_path(asstr(pbuf));
	iov[0].is_creation = true;
	iov[0].offset = 0;
	iov[0].data = (char *)"This is file-1.txt.";
	iov[0].length = strlen(iov[0].data);

	pbuf = new_auto_buf(PATH_MAX);
	tc_path_join_s(toslice(srcdir), toslice(fname2), pbuf);
	iov[1].file = tc_file_from_path(asstr(pbuf));
	iov[1].is_creation = true;
	iov[1].offset = 0;
	iov[1].data = (char *)"This is file-2.txt.";
	iov[1].length = strlen(iov[1].data);

	pbuf = new_auto_buf(PATH_MAX);
	tc_path_join_s(toslice(dstdir), toslice(fname1), pbuf);
	iov[2].file = tc_file_from_path(asstr(pbuf));
	iov[2].is_creation = true;
	iov[2].offset = 0;
	iov[2].data = NULL;
	iov[2].length = 0;

	pbuf = new_auto_buf(PATH_MAX);
	tc_path_join_s(toslice(dstdir), toslice(fname2), pbuf);
	iov[3].file = tc_file_from_path(asstr(pbuf));
	iov[3].is_creation = true;
	iov[3].offset = 0;
	iov[3].data = NULL;
	iov[3].length = 0;

	/* Write the file using NFS compounds; nfs4_writev() will open the file
	 * with CREATION flag, write to it, and then close it. */
	res = tc_writev(iov, 4, false);

	/* Check results. */
	if (res.okay) {
		fprintf(stderr,
			"Successfully write files: %d bytes in %s; %d bytes "
			"in %s via NFS.\n",
			iov[0].length, fname1, iov[1].length, fname2);
	} else {
		fprintf(stderr,
			"Failed to write file at the %d-th operation "
			"with error code %d (%s). See log file for details: "
			"%s\n",
			res.index, res.err_no,
			strerror(res.err_no),
			DEFAULT_LOG_FILE);
		goto exit;
	}

	pairs[0].src_path = iov[0].file.path;
	pairs[0].dst_path = iov[2].file.path;
	pairs[0].src_offset = 0;
	pairs[0].dst_offset = 0;
	pairs[0].length = iov[0].length;

	pairs[1].src_path = iov[1].file.path;
	pairs[1].dst_path = iov[3].file.path;
	pairs[1].src_offset = 0;
	pairs[1].dst_offset = 0;
	pairs[1].length = iov[1].length;

	res = tc_copyv(pairs, 2, false);

	if (!res.okay) {
		fprintf(stderr,
			"Failed to copy files at the %d-th operation: %s",
			res.index, strerror(res.err_no));
	}

exit:
	tc_deinit(context);

	return res.okay ? 0 : res.err_no;
}
