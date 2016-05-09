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

#define DEFAULT_LOG_FILE "/tmp/tc_test_open.log"

#define TC_TEST_NFS_FILE0 "/vfs0/test/abcd0"
#define TC_TEST_NFS_FILE1 "/vfs0/test/abcd1"

int main(int argc, char *argv[])
{
	void *context = NULL;
	int rc = -1;
	tc_res res;
	tc_file *tcf;

	/* Locate and use the default config file.  Please update the config
	 * file to the correct NFS server. */
	readlink("/proc/self/exe", exe_path, PATH_MAX);
	snprintf(tc_config_path, PATH_MAX,
		 "%s/../../../config/vfs.proxy.conf", dirname(exe_path));
	fprintf(stderr, "using config file: %s\n", tc_config_path);

	/* Initialize TC services and daemons */
	context = tc_init(tc_config_path, DEFAULT_LOG_FILE, 77);
	if (context == NULL) {
		NFS4_ERR("Error while initializing tc_client using config "
			 "file: %s; see log at %s",
			 tc_config_path, DEFAULT_LOG_FILE);
		return EIO;
	}

	/* Read the file; nfs4_readv() will open it first if needed. */
	tcf = tc_open(TC_TEST_NFS_FILE0, O_RDWR, 0);
	if (tcf->fd < 0) {
		NFS4_DEBUG("Cannot open %s", TC_TEST_NFS_FILE0);
	}

	rc = tc_close(tcf);
	if (rc < 0) {
		NFS4_DEBUG("Cannot close %d", tcf->fd);
	}

	tcf = tc_open(TC_TEST_NFS_FILE1, O_WRONLY | O_CREAT, 0);
	if (tcf->fd < 0) {
		NFS4_DEBUG("Cannot open %s", TC_TEST_NFS_FILE1);
	}

	rc = tc_close(tcf);
	if (rc < 0) {
		NFS4_DEBUG("Cannot close %d", tcf->fd);
	}

	tc_deinit(context);

	return res.okay ? 0 : res.err_no;
}
