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
tc_res posix_writev(struct tc_iovec *writes, int write_count, bool is_transaction);

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
tc_res tc_setattrsv(struct tc_attrs *attrs, int count, bool is_transaction);

#ifdef __cplusplus
}
#endif

#endif  // __TC_IMPL_POSIX_H__
