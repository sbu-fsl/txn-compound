/**
 * TC interface implementation using NFS4 compounds.
 */
#ifndef __TC_IMPL_NFS4_H__
#define __TC_IMPL_NFS4_H__

#include "tc_api.h"

#define NFS4_ERR(fmt, args...) LogCrit(COMPONENT_TC_NFS4, fmt, ##args)
#define NFS4_WARN(fmt, args...) LogWarn(COMPONENT_TC_NFS4, fmt, ##args)
#define NFS4_INFO(fmt, args...) LogInfo(COMPONENT_TC_NFS4, fmt, ##args)
#define NFS4_DEBUG(fmt, args...) LogDebug(COMPONENT_TC_NFS4, fmt, ##args)

#ifdef __cplusplus
extern "C" {
#endif

void *nfs4_init(const char *config_path, const char *log_path,
		uint16_t exprot_id);

void nfs4_deinit(void *arg);

/**
 * @reads - Array of reads for one or more files
 *         Contains file-path, read length, offset, etc.
 * @read_count - Length of the above array
 *              (Or number of reads)
 */
tc_res nfs4_readv(struct tc_iovec *reads, int read_count, bool is_transaction);

/**
 * @writes - Array of writes for one or more files
 *          Contains file-path, write length, offset, etc.
 * @read_count - Length of the above array
 *              (Or number of reads)
 */
tc_res nfs4_writev(struct tc_iovec *writes, int write_count,
		   bool is_transaction);

/*
 * @path - Full path of the file to be opened
 * @flags - Currently supports O_RDONLY, O_WRONLY, O_RDWR, O_CREAT
 *
 * Returns tc_file with fd set
 */
tc_file nfs4_openv(char *path, int flags);

/*
 * @file - File that has to be closed
 *
 * Calls ktcclose with the right fh-stateid-seqid
 * If server is unreachable, might return failure
 */
int nfs4_closev(tc_file file);

/*
 * Close all open files which user might have forgot to close
 * To be called during tc_deinit()
 */
void nfs4_close_all();

/**
 * Get attributes of files
 *
 * @attrs: array of attributes to get
 * @count: the count of tc_attrs in the preceding array
 * @is_transaction: whether to execute the compound as a transaction
 */
tc_res nfs4_getattrsv(struct tc_attrs *attrs, int count, bool is_transaction);

/**
 * Set attributes of files.
 *
 * @attrs: array of attributes to set
 * @count: the count of tc_attrs in the preceding array
 * @is_transaction: whether to execute the compound as a transaction
 */
tc_res nfs4_setattrsv(struct tc_attrs *attrs, int count, bool is_transaction);

/**
 * Rename specfied files.
 *
 * @pairs: pair of source and destination paths
 * @count: the count of tc_pairs in the preceding array
 * @is_transaction: whether to execute the compound as a transaction
 */
tc_res nfs4_renamev(tc_file_pair *pairs, int count, bool is_transaction);

/**
 * Remove specfied files.
 *
 * @: array of files to be removed
 * @count: the count of tc_ in the preceding array
 * @is_transaction: whether to execute the compound as a transaction
 */
tc_res nfs4_removev(tc_file *tc_files, int count, bool is_transaction);

/**
 * List the content of a directory.
 *
 * @dir [IN]: the path of the directory to list
 * @masks [IN]: masks of attributes to get for listed objects
 * @max_count [IN]: the maximum number of count to list
 * @contents [OUT]: the pointer to the array of files/directories in the
 * directory.  The array and the paths in the array will be allocated
 * internally by this function; the caller is responsible for releasing the
 * memory, probably by using tc_free_attrs().
 */
tc_res nfs4_listdir(const char *dir, struct tc_attrs_masks masks, int max_count,
		    struct tc_attrs **contents, int *count);

tc_res nfs4_mkdirv(tc_file *dir, mode_t *mode, int count, bool is_transaction);

#ifdef __cplusplus
}
#endif

#endif // __TC_IMPL_NFS4_H__
