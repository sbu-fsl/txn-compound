#include "tc_impl_nfs4.h"
#include "nfs4_util.h"
#include "log.h"
#include "../MainNFSD/nfs_init.h"

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
	struct gsh_export *export = NULL;
	struct req_op_context *req_ctx = NULL;
	int rc;
	config_file_t config_struct;
	nfs_start_info_t my_nfs_start_info = { .dump_default_config = false,
					       .lw_mark_trigger = false };

	nfs_prereq_init(exec_name, host_name, -1, log_path);

	/* Set up for the signal handler.
         * Blocks the signals the signal handler will handle.
         */
        sigemptyset(&signals_to_block);
        sigaddset(&signals_to_block, SIGTERM);
        sigaddset(&signals_to_block, SIGHUP);
        sigaddset(&signals_to_block, SIGPIPE);
        if (pthread_sigmask(SIG_BLOCK, &signals_to_block, NULL) != 0)
                LogFatal(COMPONENT_MAIN,
                         "Could not start nfs daemon, pthread_sigmask failed");

	/* Parse the configuration file so we all know what is going on. */

	if (config_path == NULL) {
		LogFatal(COMPONENT_INIT,
			 "start_fsals: No configuration file named.");
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

	new_module = lookup_fsal("PROXY");
	if (new_module == NULL) {
		LogDebug(COMPONENT_FSAL, "Proxy Module Not found\n");
		return NULL;
	}

	export = get_gsh_export(export_id);
	if (export == NULL) {
		LogDebug(COMPONENT_FSAL, "Export Not found\n");
		return NULL;
	}

	LogDebug(COMPONENT_FSAL,
		 "Export %d at pseudo (%s) with path (%s) and tag (%s) \n",
		 export->export_id, export->pseudopath, export->fullpath,
		 export->FS_tag);

	req_ctx = malloc(sizeof(struct req_op_context));
	if (req_ctx == NULL) {
		LogDebug(COMPONENT_FSAL, "No memory for req_ctx\n");
		return NULL;
	}

	memset(req_ctx, 0, sizeof(struct req_op_context));
        op_ctx = req_ctx;
        op_ctx->creds = NULL;
        op_ctx->export = export;
        op_ctx->fsal_export = export->fsal_export;

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
		       cur_arg->user_arg->file.type == TC_FILE_CURRENT);
		file_path = cur_arg->user_arg->file.path;
		if (file_path != NULL) {
			cur_arg->path = strndup(file_path, PATH_MAX);
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

	if (export == NULL) {
		return result;
	}

	if (export->fsal_export->obj_ops->tc_write == NULL) {
		result.err_no = (int)ENOTSUP;
		return result;
	}

	LogDebug(COMPONENT_FSAL, "nfs4_writev() called \n");

	kern_arg = malloc(write_count * (sizeof(struct tcwrite_kargs)));

	while (i < write_count && i < MAX_WRITE_COUNT) {
		cur_arg = kern_arg + i;
		cur_arg->user_arg = arg + i;
		cur_arg->opok_handle = NULL;
		cur_arg->path = NULL;
		assert(cur_arg->user_arg->file.type == TC_FILE_PATH ||
		       cur_arg->user_arg->file.type == TC_FILE_CURRENT);
		file_path = cur_arg->user_arg->file.path;
		if (file_path != NULL) {
			cur_arg->path = strndup(file_path, PATH_MAX);
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
