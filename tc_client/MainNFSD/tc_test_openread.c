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

#define DEFAULT_LOG_FILE "/tmp/tc_test_openread.log"

#define TC_TEST_NFS_FILE0 "/vfs0/test/abcd0"
#define TC_TEST_NFS_FILE1 "/vfs0/test/abcd1"

int main(int argc, char *argv[])
{
	void *context = NULL;
	int rc = -1;
	struct tc_iovec read_iovec[4];
	tc_res res;
	tc_file file0;
	tc_file file1;

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
	file0 = nfs4_openv(TC_TEST_NFS_FILE0, O_RDWR);
	if (file0.fd < 0) {
		NFS4_DEBUG("Cannot open %s", TC_TEST_NFS_FILE0);
	}

	NFS4_DEBUG("Opened %s, %d\n", TC_TEST_NFS_FILE0, file0.fd);
	//rc = nfs4_closev(file0);
	//if (rc < 0) {
	//	NFS4_DEBUG("Cannot close %d", file0.fd);
	//}

	file1 = nfs4_openv(TC_TEST_NFS_FILE1, O_RDWR);
	if (file1.fd < 0) {
		NFS4_DEBUG("Cannot open %s", TC_TEST_NFS_FILE1);
	}

	NFS4_DEBUG("Opened %s, %d\n", TC_TEST_NFS_FILE1, file1.fd);
	//rc = nfs4_closev(file1);
	//if (rc < 0) {
	//	NFS4_DEBUG("Cannot close %d", file1.fd);
	//}

	/* Setup I/O request */
        read_iovec[0].file = file1;
        read_iovec[0].offset = 0;
        read_iovec[0].length = 16384;
        read_iovec[0].data = malloc(16384);
        assert(read_iovec[0].data);
        read_iovec[1].file = tc_file_current();
        read_iovec[1].offset = 16384;
        read_iovec[1].length = 16384;
        read_iovec[1].data = malloc(16384);
        assert(read_iovec[1].data);

        //read_iovec[2].file = file0;
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

	tc_deinit(context);

	return res.okay ? 0 : res.err_no;
}
