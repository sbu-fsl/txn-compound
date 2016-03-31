#include "config.h"

#include "fsal.h"
#include <assert.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include "ganesha_list.h"
#include "abstract_atomic.h"
#include "../MainNFSD/nfs_init.h"
#include "fsal_types.h"
#include "FSAL/fsal_commonlib.h"
#include "fs_fsal_methods.h"
#include "fsal_nfsv4_macros.h"
#include "nfs_proto_functions.h"
#include "nfs_proto_tools.h"
#include "export_mgr.h"
#include "nfs4_util.h"

void handle_detach()
{
#ifdef HAVE_DAEMON
	/* daemonize the process (fork, close xterm fds,
	 * detach from parent process) */
	if (daemon(0, 0))
		LogFatal(COMPONENT_MAIN,
			 "Error detaching process from parent: %s",
			 strerror(errno));

	/* In the child process, change the log header
	 * if not, the header will contain the parent's pid */
	set_const_log_str();
#else
	/* Step 1: forking a service process */
	switch (son_pid = fork()) {
	case -1:
		/* Fork failed */
		LogFatal(COMPONENT_MAIN,
			 "Could not start nfs daemon (fork error %d (%s)",
			 errno, strerror(errno));
		break;

	case 0:
		/* This code is within the son (that will actually work)
		 * Let's make it the leader of its group of process */
		if (setsid() == -1) {
			LogFatal(
			    COMPONENT_MAIN,
			    "Could not start nfs daemon (setsid error %d (%s)",
			    errno, strerror(errno));
		}

		/* stdin, stdout and stderr should not refer to a tty
		 * I close 0, 1 & 2  and redirect them to /dev/null */
		dev_null_fd = open("/dev/null", O_RDWR);
		if (dev_null_fd < 0)
			LogFatal(COMPONENT_MAIN,
				 "Could not open /dev/null: %d (%s)", errno,
				 strerror(errno));

		if (close(STDIN_FILENO) == -1)
			LogEvent(COMPONENT_MAIN,
				 "Error while closing stdin: %d (%s)", errno,
				 strerror(errno));
		else {
			LogEvent(COMPONENT_MAIN, "stdin closed");
			dup(dev_null_fd);
		}

		if (close(STDOUT_FILENO) == -1)
			LogEvent(COMPONENT_MAIN,
				 "Error while closing stdout: %d (%s)", errno,
				 strerror(errno));
		else {
			LogEvent(COMPONENT_MAIN, "stdout closed");
			dup(dev_null_fd);
		}

		if (close(STDERR_FILENO) == -1)
			LogEvent(COMPONENT_MAIN,
				 "Error while closing stderr: %d (%s)", errno,
				 strerror(errno));
		else {
			LogEvent(COMPONENT_MAIN, "stderr closed");
			dup(dev_null_fd);
		}

		if (close(dev_null_fd) == -1)
			LogFatal(COMPONENT_MAIN,
				 "Could not close tmp fd to /dev/null: %d (%s)",
				 errno, strerror(errno));

		/* In the child process, change the log header
		 * if not, the header will contain the parent's pid */
		set_const_log_str();
		break;

	default:
		/* This code is within the parent process,
		 * it is useless, it must die */
		LogFullDebug(COMPONENT_MAIN, "Starting a child of pid %d",
			     son_pid);
		exit(0);
		break;
	}
#endif
}
