/**
 * TC interface implementation using POSIX API.
 */
#ifndef __TC_IMPL_POSIX_H__
#define __TC_IMPL_POSIX_H__

#include "tc_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @reads - Array of reads for one or more files
 *         Contains file-path, read length, offset, etc.
 * @read_count - Length of the above array
 *              (Or number of reads)
 */
tc_res posix_readv(struct tc_iovec *reads, int read_count, bool is_transaction);

/**
 * @writes - Array of writes for one or more files
 *          Contains file-path, write length, offset, etc.
 * r@ead_count - Length of the above array
 *              (Or number of reads)
 */
tc_res posix_writev(struct tc_iovec *writes, int write_count,
		    bool is_transaction);

/**
 * Get attributes of files
 *
 * @attrs: array of attributes to get
 * @count: the count of tc_attrs in the preceding array
 * @is_transaction: whether to execute the compound as a transaction
 */
tc_res posix_getattrsv(struct tc_attrs *attrs, int count, bool is_transaction);

/**
 * Set attributes of files.
 *
 * @attrs: array of attributes to set
 * @count: the count of tc_attrs in the preceding array
 * @is_transaction: whether to execute the compound as a transaction
 */
tc_res posix_setattrsv(struct tc_attrs *attrs, int count, bool is_transaction);

/**
 * Rename specfied files.
 *
 * @pairs: pair of source and destination paths
 * @count: the count of tc_pairs in the preceding array
 * @is_transaction: whether to execute the compound as a transaction
 */
tc_res posix_renamev(tc_file_pair *pairs, int count, bool is_transaction);

/**
 * Remove specfied files.
 *
 * @: array of files to be removed
 * @count: the count of tc_ in the preceding array
 * @is_transaction: whether to execute the compound as a transaction
 */
tc_res posix_removev(tc_file *tc_files, int count, bool is_transaction);

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
tc_res posix_listdir(const char *dir, struct tc_attrs_masks masks,
		     int max_count, struct tc_attrs **contents, int *count);

tc_res posix_mkdirv(tc_file *dir, mode_t *mode, int count, bool is_transaction);

#ifdef __cplusplus
}
#endif

#endif // __TC_IMPL_POSIX_H__
