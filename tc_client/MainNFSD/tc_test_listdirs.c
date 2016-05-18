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
 * This is an example showing how to list the content of multiple directories
 * using TC API.  It has the same effect as bash command
 *
 *	ls -l /vfs0/dir{1,2,3}
 *
 * @file tc_test_listdirs.c
 * @brief Test listing multiple directories.
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

#define DEFAULT_LOG_FILE "/tmp/tc_test_listdirs.log"

static bool process_direntry(const struct tc_attrs *dentry, const char *dir,
			     void *cbarg)
{
	fprintf(stderr, "listed '%s' from directory '%s'\n", dentry->file.path,
		dir);
	return true;
}

int main(int argc, char *argv[])
{
	void *context = NULL;
	const int NDIRS = 3;
	const int NFILES = 5;
	struct tc_attrs dirs[NDIRS];
	char *path;
	tc_res tcres;
	int i, j;
	int rc;
	const char *DIR_PATHS[] = { "/vfs0/dir1", "/vfs0/dir2", "/vfs0/dir3" };
	struct tc_attrs_masks masks = {0};

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
	tcres = tc_ensure_dir("/vfs0", 0755, NULL);
	if (!tcres.okay) {
		NFS4_ERR("failed to create parent directory /vfs0");
		goto exit;
	}

	/* create directories */
	for (i = 0; i < NDIRS; ++i) {
		tc_set_up_creation(&dirs[i], DIR_PATHS[i], 0755);
	}
	tcres = tc_mkdirv(dirs, NDIRS, false);
	if (tcres.okay) {
		fprintf(stderr, "successfully created %d directories\n", NDIRS);
	} else {
		fprintf(stderr, "failed to create directories\n");
		goto exit;
	}

	/* create 5 files in each directories */
	struct tc_attrs *files = alloca(NDIRS * NFILES * sizeof(*files));
	memset(files, 0, NDIRS * NFILES * sizeof(*files));
	for (i = 0; i < NDIRS; ++i) {
		for (j = 0; j < NFILES; ++j) {
			path = alloca(PATH_MAX);
			snprintf(path, PATH_MAX, "%s/file%d", DIR_PATHS[i], j);
			tc_set_up_creation(&files[i * NFILES + j], path, 0755);
			fprintf(stderr, "set up %d-th file %s under %s\n",
				i * NFILES + j, path, DIR_PATHS[i]);
		}
	}
	/* FIXME: use tc_writev() to create files instead of directories */
	tcres = tc_mkdirv(files, NDIRS * NFILES, false);
	if (tcres.okay) {
		fprintf(stderr, "successfully created %d files\n",
			NDIRS * NFILES);
	} else {
		fprintf(stderr, "failed to create files\n");
		goto exit;
	}

	tcres = tc_listdirv(DIR_PATHS, NDIRS, masks, 0, false, process_direntry,
			    NULL, false);
	if (tcres.okay) {
		fprintf(stderr, "successfully listed %d files\n",
			NDIRS * NFILES);
	} else {
		fprintf(stderr, "failed to list files\n");
		goto exit;
	}

exit:
	tc_deinit(context);

	return tcres.okay ? 0 : tcres.err_no;
}
