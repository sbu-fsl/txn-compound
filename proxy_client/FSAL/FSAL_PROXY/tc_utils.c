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

/* Free kernel read list */
int free_kread(struct read_arg *kern_arg)
{
	struct read_arg *kern_read_arg = NULL;
	struct glist_head *kern_temp_read, *kern_temp_read1;
	glist_for_each_safe(kern_temp_read, kern_temp_read1,
			    &(kern_arg->read_list))
	{
		kern_read_arg =
		    container_of(kern_temp_read, struct read_arg, read_list);
		glist_del(kern_temp_read);
		free(kern_read_arg);
	}

	free(kern_arg);

	return 0;
}

/* Free kernel write list */
int free_kwrite(struct write_arg *kern_arg)
{
	struct write_arg *kern_write_arg = NULL;
	struct glist_head *kern_temp_write, *kern_temp_write1;
	glist_for_each_safe(kern_temp_write, kern_temp_write1,
			    &(kern_arg->write_list))
	{
		kern_write_arg =
		    container_of(kern_temp_write, struct write_arg, write_list);
		glist_del(kern_temp_write);
		free(kern_write_arg);
	}

	free(kern_arg);

	return 0;
}

/* 
 * Construct kernel read list from user read list
 * The caller should make sure the free_kread is called
 */

struct read_arg *construct_kread(struct user_read_arg *user_arg, int read_count)
{
	int i = 0;
	struct read_arg *temp_read_head = NULL;
	struct read_arg *temp_read_arg = NULL;
	struct user_read_arg *user_read_arg = NULL;
	struct glist_head *user_temp_read, *user_temp_read1;

	temp_read_head = malloc(sizeof(struct read_arg));
	temp_read_head->user_arg = user_arg;
	glist_init(&(temp_read_head->read_list));
	i++;

	glist_for_each_safe(user_temp_read, user_temp_read1,
			    &(user_arg->read_list))
	{
		if (i >= read_count) {
			break;
		}

		user_read_arg = container_of(user_temp_read,
					     struct user_read_arg, read_list);
		temp_read_arg = malloc(sizeof(struct read_arg));
		temp_read_arg->user_arg = user_read_arg;
		glist_add_tail(&(temp_read_head->read_list),
			       &(temp_read_arg->read_list));
		i++;
	}

	return temp_read_head;
}

/* 
 * Frees kernel_tcread_args
 * Calls free_kread for each arg
 */
int free_ktcread(struct kernel_tcread_args *kern_arg, int file_count)
{
	int i = 0;
	struct kernel_tcread_args *cur_arg = NULL;

	while (i < file_count) {
		cur_arg = kern_arg + i;
		free_kread(cur_arg->read_args);
		i++;
	}

	free(kern_arg);
}

/* 
 * Frees kernel_tcwrite_args
 * Calls free_kwrite for each arg
 */
int free_ktcwrite(struct kernel_tcwrite_args *kern_arg, int file_count)
{
	int i = 0;
	struct kernel_tcwrite_args *cur_arg = NULL;

	while (i < file_count) {
		cur_arg = kern_arg + i;
		free_kwrite(cur_arg->write_args);
		i++;
	}

	free(kern_arg);
}

/* 
 * Construct kernel write list from user write list
 * The caller should make sure the free_kwrite is called
 */
struct write_arg *construct_kwrite(struct user_write_arg *user_arg,
				   int write_count)
{
	int i = 0;
	struct write_arg *temp_write_head = NULL;
	struct write_arg *temp_write_arg = NULL;
	struct user_write_arg *user_write_arg = NULL;
	struct glist_head *user_temp_write, *user_temp_write1;

	temp_write_head = malloc(sizeof(struct write_arg));
	temp_write_head->user_arg = user_arg;
	glist_init(&(temp_write_head->write_list));
	i++;

	glist_for_each_safe(user_temp_write, user_temp_write1,
			    &(user_arg->write_list))
	{
		if (i >= write_count) {
			break;
		}

		user_write_arg = container_of(
		    user_temp_write, struct user_write_arg, write_list);
		temp_write_arg = malloc(sizeof(struct write_arg));
		temp_write_arg->user_arg = user_write_arg;
		glist_add_tail(&(temp_write_head->write_list),
			       &(temp_write_arg->write_list));
		i++;
	}

	return temp_write_head;
}

/* 
 * Construct kernel arg structure from user arg structure
 * The caller should make sure the free_ktcwrite is called
 */

struct kernel_tcwrite_args *construct_ktcwrite(struct user_tcwrite_args *arg,
					       int file_count)
{
	int i = 0;
	struct user_tcwrite_args *cur_arg = NULL;
	struct kernel_tcwrite_args *kernel_tcwrite_head = NULL;
	struct kernel_tcwrite_args *kernel_tcwrite_cur = NULL;

	kernel_tcwrite_cur =
	    malloc(file_count * sizeof(struct kernel_tcwrite_args));

	while (i < file_count) {
		cur_arg = arg + i;
		kernel_tcwrite_cur = kernel_tcwrite_cur + i;
		kernel_tcwrite_cur->user_arg = cur_arg;
		kernel_tcwrite_cur->write_args =
		    construct_kwrite(cur_arg->write_args, 1);
		if (kernel_tcwrite_head == NULL) {
			kernel_tcwrite_head = kernel_tcwrite_cur;
		}
		i++;
	}

	return kernel_tcwrite_head;
}

/* 
 * Construct kernel arg structure from user arg structure
 * The caller should make sure the free_ktcread is called
 */ 

struct kernel_tcread_args *construct_ktcread(struct user_tcread_args *arg,
					     int file_count)
{
	int i = 0;
	struct user_tcread_args *cur_arg = NULL;
	struct kernel_tcread_args *kernel_tcread_head = NULL;
	struct kernel_tcread_args *kernel_tcread_cur = NULL;

	kernel_tcread_cur =
	    malloc(file_count * sizeof(struct kernel_tcread_args));

	while (i < file_count) {
		cur_arg = arg + i;
		kernel_tcread_cur = kernel_tcread_cur + i;
		kernel_tcread_cur->user_arg = cur_arg;
		kernel_tcread_cur->read_args =
		    construct_kread(cur_arg->read_args, 1);
		if (kernel_tcread_head == NULL) {
			kernel_tcread_head = kernel_tcread_cur;
		}
		i++;
	}

	return kernel_tcread_head;
}

/*
 *  Send multiple reads for a single file
 *  arg - should contain the list of reads in a linked list
 *  open_mode
 *      USE_SPECIAL_STATE - The reads can be packed in a single compound
 *                          with special stateid
 *      USE_NORMAL_STATE  - First open the file, then with the stateid got,
 *                          send reads in a single compound, followed by
 *                          closing the file
 */

fsal_status_t tcread_s(struct gsh_export *export, struct user_tcread_args *arg,
		       int read_count)
{
	struct kernel_tcread_args *kern_arg = NULL;
	fsal_status_t fsal_status = { 0, 0 };

	if (export == NULL) {
		return fsalstat(ERR_FSAL_NOENT, ENOENT);
	}

	if (export->fsal_export->obj_ops->tc_read == NULL) {
		return fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
	}

	LogDebug(COMPONENT_FSAL, "tcread_s() called \n");

	kern_arg = malloc(sizeof(struct kernel_tcread_args));
	kern_arg->user_arg = arg;
	kern_arg->read_args = NULL;

	kern_arg->read_args = construct_kread(arg->read_args, MAX_READ_COUNT);

	switch (arg->open_mode) {
	case USE_SPECIAL_STATE:
		fsal_status = export->fsal_export->obj_ops->tc_read(kern_arg, 1,
								    read_count);
		break;
	case USE_NORMAL_STATE:
		fsal_status = fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
		break;
	default:
		fsal_status = fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
		break;
	}

	free_kread(kern_arg->read_args);
	free(kern_arg);
	return fsal_status;
}

/*
 * Send single read for multiple files
 * arg - assumed to be an array of user_tcread_args
 *       with file_count entries
 * open_mode
 *    USE_SPECIAL_STATE - The read can be packed in a single compound
 *                        with special stateid
 *    USE_NORMAL_STATE  - First open the files, then with the stateid got,
 *                        send reads in a single compound, followed by closing
 *                        the files
 */

fsal_status_t tcread_m(struct gsh_export *export, struct user_tcread_args *arg,
		       int file_count)
{
	struct kernel_tcread_args *kern_arg = NULL;
	fsal_status_t fsal_status = { 0, 0 };

	if (export == NULL) {
		return fsalstat(ERR_FSAL_NOENT, ENOENT);
	}

	if (export->fsal_export->obj_ops->tc_read == NULL) {
		return fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
	}

	LogDebug(COMPONENT_FSAL, "tcread_m() called \n");

	kern_arg = construct_ktcread(arg, file_count);

	switch (arg->open_mode) {
	case USE_SPECIAL_STATE:
		fsal_status = export->fsal_export->obj_ops->tc_read(
		    kern_arg, file_count, 1);
		break;
	case USE_NORMAL_STATE:
		fsal_status = fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
		break;
	default:
		fsal_status = fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
		break;
	}

	free_ktcread(kern_arg, file_count);
	return fsal_status;
}

/*
 *  Send multiple writes for a single file
 *  arg - should contain the list of writes in a linked list
 *  open_mode
 *      USE_SPECIAL_STATE - The writes can be packed in a single compound
 *                          with special stateid
 *      USE_NORMAL_STATE  - First open the file, then with the stateid got,
 *                          send writes in a single compound, followed by
 *                          closing the file
 */

fsal_status_t tcwrite_s(struct gsh_export *export,
			struct user_tcwrite_args *arg, int write_count)
{
	struct kernel_tcwrite_args *kern_arg = NULL;
	fsal_status_t fsal_status = { 0, 0 };

	if (export == NULL) {
		return fsalstat(ERR_FSAL_NOENT, ENOENT);
	}

	if (export->fsal_export->obj_ops->tc_write == NULL) {
		return fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
	}

	LogDebug(COMPONENT_FSAL, "tcwrite_s() called \n");

	kern_arg = malloc(sizeof(struct kernel_tcwrite_args));
	kern_arg->user_arg = arg;
	kern_arg->write_args = NULL;

	kern_arg->write_args =
	    construct_kwrite(arg->write_args, MAX_WRITE_COUNT);

	switch (arg->open_mode) {
	case USE_SPECIAL_STATE:
		fsal_status = export->fsal_export->obj_ops->tc_write(
		    kern_arg, 1, write_count);
		break;
	case USE_NORMAL_STATE:
		fsal_status = fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
		break;
	default:
		fsal_status = fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
		break;
	}

	free_kwrite(kern_arg->write_args);
	free(kern_arg);
	return fsal_status;
}

/*
 * Send single write for multiple files
 * arg - assumed to be an array of user_tcwrite_args
 *       with file_count entries
 * open_mode
 *    USE_SPECIAL_STATE - The writes can be packed in a single compound
 *                        with special stateid
 *    USE_NORMAL_STATE  - First open the files, then with the stateid got,
 *                        send writes in a single compound, followed by closing
 *                        the files
 */

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

