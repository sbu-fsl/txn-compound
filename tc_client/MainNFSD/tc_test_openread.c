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
 *
 * @file tc_test_openread.c
 * @brief Test mixing read using FD and Path.
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

static char exe_path[PATH_MAX];
static char tc_config_path[PATH_MAX];

#define DEFAULT_LOG_FILE "/tmp/tc_test_openread.log"

#define TC_TEST_NFS_FILE0 "/vfs0/test/abcd0"
#define TC_TEST_NFS_FILE1 "/vfs0/test/abcd1"

int main(int argc, char *argv[])
{
	void *context = NULL;
	int rc = -1;
	struct tc_iovec read_iovec[4];
	tc_res res;
	tc_file *file1;

	/* Locate and use the default config file.  Please update the config
	 * file to the correct NFS server. */
	readlink("/proc/self/exe", exe_path, PATH_MAX);
	snprintf(tc_config_path, PATH_MAX,
		 "%s/../../../config/tc.proxy.conf", dirname(exe_path));
	fprintf(stderr, "using config file: %s\n", tc_config_path);

	/* Initialize TC services and daemons */
	context = tc_init(tc_config_path, DEFAULT_LOG_FILE, 77);
	if (context == NULL) {
		NFS4_ERR("Error while initializing tc_client using config "
			 "file: %s; see log at %s",
			 tc_config_path, DEFAULT_LOG_FILE);
		return EIO;
	}

	file1 = nfs4_open(TC_TEST_NFS_FILE1, O_RDWR, 0);
	if (file1->fd < 0) {
		NFS4_DEBUG("Cannot open %s", TC_TEST_NFS_FILE1);
	}

	NFS4_DEBUG("Opened %s, %d\n", TC_TEST_NFS_FILE1, file1->fd);

	/* Setup I/O request */
        read_iovec[0].file = *file1;
        read_iovec[0].offset = 0;
        read_iovec[0].length = 16384;
        read_iovec[0].data = malloc(16384);
        assert(read_iovec[0].data);
        read_iovec[1].file = tc_file_current();
        read_iovec[1].offset = 16384;
        read_iovec[1].length = 16384;
        read_iovec[1].data = malloc(16384);
        assert(read_iovec[1].data);

        read_iovec[2].file = tc_file_from_path(TC_TEST_NFS_FILE0);
        read_iovec[2].offset = 0;
        read_iovec[2].length = 16384;
        read_iovec[2].data = malloc(16384);
        assert(read_iovec[2].data);
        read_iovec[3].file = tc_file_current();
        read_iovec[3].offset = 16384;
        read_iovec[3].length = 16384;
        read_iovec[3].data = malloc(16384);
        assert(read_iovec[3].data);

	read_iovec[2].is_creation = 1;
        res = tc_writev(read_iovec, 4, false);

        /* Read the file; nfs4_readv() will open it first if needed. */
        res = tc_readv(read_iovec, 4, false);


        /* Check results. */
	if (res.okay) {
		fprintf(stderr,
			"Successfully read the first %d bytes of file \"%s\" "
			"via NFS.\n",
			read_iovec[0].length, TC_TEST_NFS_FILE0);
	} else {
		fprintf(stderr,
			"Failed to read file \"%s\" at the %d-th operation "
			"with error code %d (%s). See log file for details: "
			"%s\n",
			TC_TEST_NFS_FILE0, res.index, res.err_no,
			strerror(res.err_no), DEFAULT_LOG_FILE);
	}

	rc = nfs4_close(file1);
	if (rc < 0) {
		NFS4_DEBUG("Cannot close %d", file1->fd);
	}
	tc_deinit(context);

	return res.okay ? 0 : res.err_no;
}
