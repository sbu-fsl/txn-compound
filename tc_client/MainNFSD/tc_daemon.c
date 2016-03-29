/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright CEA/DAM/DIF  (2008)
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * ---------------------------------------
 */

/**
 * @file nfs_main.c
 * @brief The file that contain the 'main' routine for the nfsd.
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
#include "fsal_pnfs.h"
#include "tc_user.h"

config_file_t config_struct;

int main(int argc, char *argv[])
{
	struct fsal_module* module = NULL;
	int rc = 0;

	module = tc_init("/home/ashok/log_ganesha",
			 "/home/ashok/work/fsl/fsl-nfs-ganesha/secnfs/"
			 "config/vfs.proxy.conf",
			 77);

	if (module == NULL) {
		LogFatal(COMPONENT_INIT, "Error while initializing tc_client");
	}

	/* Everything seems to be OK! We can now start service threads */
	tc_singlefile("/vfs0/test_cdist/abcd", 1048576, 1, 2000000, 1, 0.0, 0);

	tc_deinit(module);

	return 0;

}
