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

#include <unistd.h>
#include "tc_impl_nfs4.h"
#include "nfs4_util.h"
#include "log.h"
#include "fsal_types.h"
#include "../MainNFSD/nfs_init.h"

#define TC_FILE_START 0

/*
 * Initialize tc_client
 * log_path - Location of the log file
 * config_path - Location of the config file
 * export_id - Export id of the export configured in the conf file
 *
 * This returns fsal_module pointer to tc_client module
 * If tc_client module does not exist, it will return NULL
 *
 * Caller of this function should call tc_deinit() after use
 */
void *nfs4_init(const char *config_path, const char *log_path,
		uint16_t export_id)
{
	char *exec_name = "nfs-ganesha";
	char *host_name = "localhost";
	struct fsal_module *new_module = NULL;
	sigset_t signals_to_block;
	struct config_error_type err_type;
	struct gsh_export *exp = NULL;
	int rc;
	config_file_t config_struct;
	nfs_start_info_t my_nfs_start_info = { .dump_default_config = false,
					       .lw_mark_trigger = false };

	nfs_prereq_init(exec_name, host_name, -1, log_path);

	/* Set up for the signal handler.
         * Blocks the signals the signal handler will handle.
         */
        sigemptyset(&signals_to_block);
        sigaddset(&signals_to_block, SIGHUP);
        sigaddset(&signals_to_block, SIGPIPE);
        if (pthread_sigmask(SIG_BLOCK, &signals_to_block, NULL) != 0)
                LogFatal(COMPONENT_MAIN,
                         "Could not start nfs daemon, pthread_sigmask failed");

	/* Parse the configuration file so we all know what is going on. */

	if (access(config_path, R_OK) != 0) {
		LogFatal(COMPONENT_INIT,
			 "nfs_init(): cannot read configuration file: %s.",
			 config_path);
		return NULL;
	}

	config_struct = config_ParseFile(config_path, &err_type);

	if (!config_error_no_error(&err_type)) {
		char *errstr = err_type_str(&err_type);

		if (!config_error_is_harmless(&err_type))
			LogFatal(
			    COMPONENT_INIT,
			    "Fatal error while parsing %s because of %s errors",
			    config_path, errstr != NULL ? errstr : "unknown");
		/* NOT REACHED */
		LogCrit(COMPONENT_INIT, "Minor parse errors found %s in %s",
			errstr != NULL ? errstr : "unknown", config_path);
		if (errstr != NULL)
			gsh_free(errstr);
	}

	if (read_log_config(config_struct) < 0)
		LogFatal(COMPONENT_INIT,
			 "Error while parsing log configuration");
	/* We need all the fsal modules loaded so we can have
	 * the list available at exports parsing time.
	 */
	start_fsals();

	/* parse configuration file */

	if (nfs_set_param_from_conf(config_struct, &my_nfs_start_info)) {
                LogFatal(COMPONENT_INIT,
                         "Error setting parameters from configuration file.");
        }

	/* initialize core subsystems and data structures */
        if (init_server_pkgs() != 0)
                LogFatal(COMPONENT_INIT,
                         "Failed to initialize server packages");

        /* Load export entries from parsed file
         * returns the number of export entries.
         */
        rc = ReadExports(config_struct);
        if (rc < 0)
                LogFatal(COMPONENT_INIT,
                          "Error while parsing export entries");
        else if (rc == 0)
                LogWarn(COMPONENT_INIT,
                        "No export entries found in configuration file !!!");

        /* freeing syntax tree : */

        config_Free(config_struct);

	new_module = lookup_fsal("TCNFS");
	if (new_module == NULL) {
		LogDebug(COMPONENT_FSAL, "TCNFS Module Not found\n");
		return NULL;
	}

	exp = get_gsh_export(export_id);
	if (exp == NULL) {
		LogDebug(COMPONENT_FSAL, "Export Not found\n");
		return NULL;
	}

	LogDebug(COMPONENT_FSAL,
		 "Export %d at pseudo (%s) with path (%s) and tag (%s)",
		 exp->export_id, exp->pseudopath, exp->fullpath,
		 exp->FS_tag);

	sleep(1);

	// op_ctx is a symbol (pointer) from the shared library
	op_ctx = calloc(1, sizeof(*op_ctx));
	if (op_ctx == NULL) {
		LogDebug(COMPONENT_FSAL, "No memory for op_ctx\n");
		return NULL;
	}

	op_ctx->creds = NULL;
	op_ctx->export = exp;
	op_ctx->fsal_export = exp->fsal_export;

	rc = nfs4_chdir(exp->fullpath);
	assert(rc == 0);

	sleep(1);

	init_fd();
	return (void*)new_module;
}

/*
 * Free the reference to module and op_ctx
 * Should be called if nfs4_init() was called previously
 */
void nfs4_deinit(void *arg)
{
	struct fsal_module *module = NULL;

	/* Close all open fds, client might have forgot to close them */
	nfs4_close_all();

	if (op_ctx != NULL) {
		free(op_ctx);
		op_ctx = NULL;
	}

	module = (struct fsal_module*) arg;
	if (module != NULL) {
		LogDebug(COMPONENT_FSAL, "Dereferencing tc_client module\n");
		// In tc_init(), two references of the module are taken, one by
		// load_fsal() called via commit_fsal() during config loading,
		// and lookup_fsal() explicitly in tc_init().
		fsal_put(module);  /* for lookup_fsal() */
		fsal_put(module);  /* for load_fsal() */
	}
}

/*
 * arg - Array of reads for one or more files
 *       Contains file-path, read length, offset, etc.
 * read_count - Length of the above array
 *              (Or number of reads)
 */
tc_res nfs4_readv(struct tc_iovec *arg, int read_count, bool is_transaction)
{
	struct tcread_kargs *kern_arg = NULL;
	struct tcread_kargs *cur_arg = NULL;
	fsal_status_t fsal_status = { 0, 0 };
	int i = 0;
	struct gsh_export *export = op_ctx->export;
	tc_res result = { .okay = false, .index = 0, .err_no = (int)ENOENT };
	const char *file_path = NULL;
	stateid4 *sid = NULL;
	nfs_fh4 *fh = NULL;
	int last_op = TC_FILE_START;

	if (export == NULL) {
		return result;
	}

	if (export->fsal_export->obj_ops->tc_read == NULL) {
		result.err_no = (int)ENOTSUP;
		return result;
	}

	LogDebug(COMPONENT_FSAL, "nfs4_readv() called\n");

	kern_arg = malloc(read_count * (sizeof(struct tcread_kargs)));

	while (i < read_count && i < MAX_READ_COUNT) {
		cur_arg = kern_arg + i;
		cur_arg->user_arg = arg + i;
		cur_arg->opok_handle = NULL;
		cur_arg->path = NULL;
		assert(cur_arg->user_arg->file.type == TC_FILE_PATH ||
		       cur_arg->user_arg->file.type == TC_FILE_DESCRIPTOR ||
		       cur_arg->user_arg->file.type == TC_FILE_CURRENT);

		switch (cur_arg->user_arg->file.type) {
		case TC_FILE_DESCRIPTOR:
			if (fd_in_use(cur_arg->user_arg->file.fd) < 0) {
				result.err_no = (int)EINVAL;
				goto error;
			}

			sid = cur_arg->sid =
			    &fd_list[cur_arg->user_arg->file.fd].stateid;
			fh = cur_arg->fh =
			    &fd_list[cur_arg->user_arg->file.fd].fh;
			last_op = TC_FILE_DESCRIPTOR;
			break;
		case TC_FILE_PATH:
			file_path = cur_arg->user_arg->file.path;
			if (file_path != NULL) {
				cur_arg->path = strndup(file_path, PATH_MAX);
			}

			sid = NULL;
			fh = NULL;
			last_op = TC_FILE_PATH;
			break;
		case TC_FILE_CURRENT:
			cur_arg->sid = sid;
			cur_arg->fh = fh;
			break;
		}

		// cur_arg->read_ok = NULL;
		i++;
	}

	fsal_status = export->fsal_export->obj_ops->tc_read(
	    kern_arg, read_count, &result.index);

	i = 0;
	while (i < read_count && i < MAX_READ_COUNT) {
		cur_arg = kern_arg + i;
		if (cur_arg->path != NULL) {
			free(cur_arg->path);
		}
		i++;
	}

	free(kern_arg);

	if (FSAL_IS_ERROR(fsal_status)) {
		result.err_no = (int)fsal_status.major;
		LogDebug(COMPONENT_FSAL, "tcread failed at index: %d\n",
			 result.index);
		return result;
	}

	result.okay = true;
	return result;

error:
	free(kern_arg);
	return result;
}

/*
 * arg - Array of writes for one or more files
 *       Contains file-path, write length, offset, etc.
 * read_count - Length of the above array
 *              (Or number of reads)
 */
tc_res nfs4_writev(struct tc_iovec *arg, int write_count, bool is_transaction)
{
	struct tcwrite_kargs *kern_arg = NULL;
	struct tcwrite_kargs *cur_arg = NULL;
	fsal_status_t fsal_status = { 0, 0 };
	int i = 0;
	struct gsh_export *export = op_ctx->export;
	tc_res result = { .okay = false, .index = 0, .err_no = (int)ENOENT };
	const char *file_path = NULL;
	stateid4 *sid = NULL;
	nfs_fh4 *fh = NULL;
	int last_op = TC_FILE_START;

	if (export == NULL) {
		return result;
	}

	if (export->fsal_export->obj_ops->tc_write == NULL) {
		result.err_no = (int)ENOTSUP;
		return result;
	}

	LogDebug(COMPONENT_FSAL, "nfs4_writev() called \n");

	kern_arg = calloc(write_count, (sizeof(struct tcwrite_kargs)));

	while (i < write_count && i < MAX_WRITE_COUNT) {
		cur_arg = kern_arg + i;
		cur_arg->user_arg = arg + i;
		cur_arg->opok_handle = NULL;
		cur_arg->path = NULL;
		assert(cur_arg->user_arg->file.type == TC_FILE_PATH ||
                       cur_arg->user_arg->file.type == TC_FILE_DESCRIPTOR ||
                       cur_arg->user_arg->file.type == TC_FILE_CURRENT);

		switch (cur_arg->user_arg->file.type) {
		case TC_FILE_DESCRIPTOR:
			if (fd_in_use(cur_arg->user_arg->file.fd) < 0) {
                                result.err_no = (int)EINVAL;
                                goto error;
                        }

			sid = cur_arg->sid =
			    &fd_list[cur_arg->user_arg->file.fd].stateid;
			fh = cur_arg->fh =
			    &fd_list[cur_arg->user_arg->file.fd].fh;
			last_op = TC_FILE_DESCRIPTOR;

			break;
		case TC_FILE_PATH:
			file_path = cur_arg->user_arg->file.path;
			if (file_path != NULL) {
				cur_arg->path = strndup(file_path, PATH_MAX);
			}
			sid = NULL;
			fh = NULL;
			last_op = TC_FILE_PATH;

			break;
		case TC_FILE_CURRENT:
			cur_arg->sid = sid;
			cur_arg->fh = fh;

			break;
		}
		// cur_arg->write_ok = NULL;
		i++;
	}

	fsal_status = export->fsal_export->obj_ops->tc_write(
	    kern_arg, write_count, &result.index);

	i = 0;
	while (i < write_count && i < MAX_WRITE_COUNT) {
		cur_arg = kern_arg + i;
		if (cur_arg->path != NULL) {
			free(cur_arg->path);
		}
		i++;
	}

	free(kern_arg);

	if (FSAL_IS_ERROR(fsal_status)) {
		result.err_no = (int)fsal_status.major;
		LogDebug(COMPONENT_FSAL, "tcwrite failed at index: %d\n",
			 result.index);
		return result;
	}

	result.okay = true;
	return result;

error:
	free(kern_arg);
	return result;
}

/*
 * arg - Array of writes for one or more files
 *       Contains file-path, write length, offset, etc.
 * read_count - Length of the above array
 *              (Or number of reads)
 */
tc_file nfs4_openv(char *path, int flags)
{
	struct tcopen_kargs kern_arg;
	tc_file ret_file = { .fd = -1, .type = TC_FILE_DESCRIPTOR};
	fsal_status_t fsal_status = { 0, 0 };
	int i = 0;
	struct gsh_export *export = op_ctx->export;
	const char *file_path = NULL;

	if (export == NULL) {
		goto exit;
	}

	if (export->fsal_export->obj_ops->tc_open == NULL) {
		goto exit;
	}

	if (path == NULL) {
		goto exit;
	}

	LogDebug(COMPONENT_FSAL, "nfs4_openv() called \n");

	kern_arg.opok_handle = NULL;
	kern_arg.fhok_handle = NULL;
	kern_arg.path = path;
	memset(&kern_arg.attrib, 0, sizeof(struct attrlist));

	if (get_freecount() <= 0) {
		goto exit;
	}

	fsal_status = export->fsal_export->obj_ops->tc_open(&kern_arg, flags);

	if (FSAL_IS_ERROR(fsal_status)) {
		goto exit;
	}

	ret_file.fd =
	    get_fd(&kern_arg.opok_handle->stateid, &kern_arg.fhok_handle->object);
	ret_file.type = TC_FILE_DESCRIPTOR;

	free(kern_arg.fhok_handle->object.nfs_fh4_val);

	/*
	 * Need to increment seqid because tc_open calls both OPEN and
	 * OPEN_CONFIRM
	 */
	incr_seqid(ret_file.fd);
	incr_seqid(ret_file.fd);
exit:
	return ret_file;
}

int nfs4_closev(tc_file user_file)
{
	fsal_status_t fsal_status = { 0, 0 };
	struct gsh_export *export = op_ctx->export;

	if (fd_in_use(user_file.fd) < 0) {
		return -1;
	}

	fsal_status = export->fsal_export->obj_ops->tc_close(
	    &fd_list[user_file.fd].fh, &fd_list[user_file.fd].stateid,
	    &fd_list[user_file.fd].seqid);
	if (FSAL_IS_ERROR(fsal_status)) {
		return (int)EAGAIN;
	}

	incr_seqid(
	    user_file.fd); // Not needed, but example of how to use incr_seqid
	freefd(user_file.fd);

	return 0;
}

void nfs4_close_all()
{
	int i = 0;
	tc_file file = {.fd = -1, .type = TC_FILE_DESCRIPTOR};

	while (i < MAX_FD) {
		if (fd_list[i].fd >= 0) {
			file.fd = i;
			nfs4_closev(file);
		}
		i++;
	}
}

tc_res nfs4_getattrsv(struct tc_attrs *attrs, int count, bool is_transaction)
{
	struct gsh_export *exp = op_ctx->export;
	tc_res res;

	res = exp->fsal_export->obj_ops->tc_getattrsv(attrs, count);

	return res;
}

tc_res nfs4_setattrsv(struct tc_attrs *attrs, int count, bool is_transaction)
{
	struct gsh_export *exp = op_ctx->export;
	tc_res res;

	res = exp->fsal_export->obj_ops->tc_setattrsv(attrs, count);

	return res;
}

tc_res nfs4_mkdirv(struct tc_attrs *dirs, int count, bool is_transaction)
{
	struct gsh_export *exp = op_ctx->export;
	tc_res res;

	res = exp->fsal_export->obj_ops->tc_mkdirv(dirs, count);

	return res;
}

struct _tc_attrs_array {
	struct tc_attrs *attrs;
	size_t size;
	size_t capacity;
};

static bool fill_dir_entries(const struct tc_attrs *entry, const char *dir,
			     void *cbarg)
{
	struct _tc_attrs_array *parray = (struct _tc_attrs_array *)cbarg;
	parray->attrs[parray->size++] = *entry;
}

tc_res nfs4_listdir(const char *dir, struct tc_attrs_masks masks, int max_count,
		    struct tc_attrs **contents, int *count)
{
	tc_res tcres;
	struct _tc_attrs_array atarray;
	atarray.attrs = calloc(max_count, sizeof(struct tc_attrs));
	if (!atarray.attrs) {
		return tc_failure(0, ENOMEM);
	}
	atarray.size = 0;
	atarray.capacity = max_count;

	tcres = nfs4_listdirv(&dir, 1, masks, max_count, fill_dir_entries,
			      &atarray, false);
	if (!tcres.okay) {
		tc_free_attrs(atarray.attrs, atarray.size, true);
	}

	*contents = atarray.attrs;
	*count = atarray.size;
	return tcres;
}

tc_res nfs4_listdirv(const char **dirs, int count, struct tc_attrs_masks masks,
		     int max_entries, tc_listdirv_cb cb, void *cbarg,
		     bool is_transaction)
{
	struct gsh_export *exp = op_ctx->export;
	tc_res res;

	res = exp->fsal_export->obj_ops->tc_listdirv(dirs, count, masks,
						     max_entries, cb, cbarg);

	return res;
}

tc_res nfs4_renamev(tc_file_pair *pairs, int count, bool is_transaction)
{
	struct gsh_export *exp = op_ctx->export;
	tc_res res;

	res = exp->fsal_export->obj_ops->tc_renamev(pairs, count);

	return res;
}

tc_res nfs4_removev(tc_file *files, int count, bool is_transaction)
{
	struct gsh_export *exp = op_ctx->export;
	tc_res res;

	res = exp->fsal_export->obj_ops->tc_removev(files, count);

	return res;
}

int nfs4_chdir(const char *path)
{
	struct gsh_export *exp = op_ctx->export;

	assert(exp->fullpath);
	if (strncmp(path, exp->fullpath, strlen(exp->fullpath)) != 0) {
		NFS4_ERR("cannot set TC working directory to %s because it is "
			 "outside of NFS export %s", path, exp->fullpath);
		return -EINVAL;
	}

	return exp->fsal_export->obj_ops->tc_chdir(path);
}

char *nfs4_getcwd()
{
	return op_ctx->fsal_export->obj_ops->tc_getcwd();
}
