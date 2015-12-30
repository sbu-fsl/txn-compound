#include "config.h"

#include "fsal.h"
#include <assert.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include "ganesha_list.h"
#include "abstract_atomic.h"
#include "fsal_types.h"
#include "FSAL/fsal_commonlib.h"
#include "pxy_fsal_methods.h"
#include "fsal_nfsv4_macros.h"
#include "nfs_proto_functions.h"
#include "nfs_proto_tools.h"
#include "export_mgr.h"
#include "tc_utils.h"

/*
 *  Send multiple reads for a single file
 *  arg - should contain the list of reads in a linked list
 *        Caller has to make sure all the fields inside arg are allocated
 *        and freed
 *  open_mode
 *      USE_SPECIAL_STATE - The reads can be packed in a single compound
 *                          with special stateid
 *      USE_NORMAL_STATE  - First open the file, then with the stateid got,
 *                          send reads in a single compound, followed by
 *                          closing the file
 */

fsal_status_t tcread_v(struct gsh_export *export, struct tc_iovec *arg,
		       int read_count, bool is_transaction)
{
	struct kernel_tcread_args *kern_arg = NULL;
	struct kernel_tcread_args *cur_arg = NULL;
	fsal_status_t fsal_status = { 0, 0 };
	int i = 0;

	if (export == NULL) {
		return fsalstat(ERR_FSAL_NOENT, ENOENT);
	}

	if (export->fsal_export->obj_ops->tc_read == NULL) {
		return fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
	}

	LogDebug(COMPONENT_FSAL, "tcread_v() called \n");

	kern_arg = malloc(read_count * (sizeof(struct kernel_tcread_args)));

	while (i < read_count && i < MAX_READ_COUNT) {
		cur_arg = kern_arg + i;
		cur_arg->user_arg = arg + i;
		cur_arg->opok_handle = NULL;
		//cur_arg->read_ok = NULL;
		i++;
	}

	fsal_status =
	    export->fsal_export->obj_ops->tc_read(kern_arg, read_count);

	free(kern_arg);

	return fsal_status;
}

/*
 * Send single write for multiple files
 * arg - assumed to be an array of user_tcwrite_args
 *       with file_count entries
 *       Caller has to make sure all the fields inside arg are allocated
 *       and freed
 * open_mode
 *    USE_SPECIAL_STATE - The writes can be packed in a single compound
 *                        with special stateid
 *    USE_NORMAL_STATE  - First open the files, then with the stateid got,
 *                        send writes in a single compound, followed by closing
 *                        the files
 */
/*
fsal_status_t tcwrite_m(struct gsh_export *export,
			struct user_tcwrite_args *arg, int file_count)
{
	struct kernel_tcwrite_args *kern_arg = NULL;
	fsal_status_t fsal_status = { 0, 0 };

	if (export == NULL) {
		return fsalstat(ERR_FSAL_NOENT, ENOENT);
	}

	if (export->fsal_export->obj_ops->tc_write == NULL) {
		return fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
	}

	LogDebug(COMPONENT_FSAL, "tcwrite_m() called \n");

	kern_arg = construct_ktcwrite(arg, file_count);

	switch (arg->open_mode) {
	case USE_SPECIAL_STATE:
		fsal_status = export->fsal_export->obj_ops->tc_write(
		    kern_arg, file_count, 1);
		break;
	case USE_NORMAL_STATE:
		fsal_status = fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
		break;
	default:
		fsal_status = fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
		break;
	}

	free_ktcwrite(kern_arg, file_count);
	return fsal_status;
}
*/
