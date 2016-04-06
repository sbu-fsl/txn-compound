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
 * @file tc_test_read.c
 * @brief Test read a small file from NFS using TC.
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

#define DEFAULT_LOG_FILE "/tmp/tc_test_read.log"

#define TC_TEST_NFS_FILE "/vfs0/tcdir/abcd"

int main(int argc, char *argv[])
{
	void *context = NULL;
	struct tc_iovec read_iovec;
	tc_res res;

	/* Locate and use the default config file.  Please update the config
	 * file to the correct NFS server. */
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

	/* Setup I/O request */
	read_iovec.file = tc_file_from_path(TC_TEST_NFS_FILE);
	read_iovec.offset = 0;
	read_iovec.length = 4096;
	read_iovec.data = malloc(4096);
	assert(read_iovec.data);

	/* Read the file; nfs4_readv() will open it first if needed. */
	res = tc_readv(&read_iovec, 1, false);

	/* Check results. */
	if (res.okay) {
		fprintf(stderr,
			"Successfully read the first %d bytes of file \"%s\" "
			"via NFS.\n",
			read_iovec.length, TC_TEST_NFS_FILE);
	} else {
		fprintf(stderr,
			"Failed to read file \"%s\" at the %d-th operation "
			"with error code %d (%s). See log file for details: "
			"%s\n",
			TC_TEST_NFS_FILE, res.index, res.err_no,
			strerror(res.err_no),
			DEFAULT_LOG_FILE);
	}

	tc_deinit(context);

	return res.okay ? 0 : res.err_no;
}
