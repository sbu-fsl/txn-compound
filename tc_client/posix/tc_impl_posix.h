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

/**
 * TC interface implementation using POSIX API.
 */

#ifndef __TC_IMPL_POSIX_H__
#define __TC_IMPL_POSIX_H__

#include "tc_api.h"

#define POSIX_ERR(fmt, args...) LogCrit(COMPONENT_TC_POSIX, fmt, ##args)
#define POSIX_WARN(fmt, args...) LogWarn(COMPONENT_TC_POSIX, fmt, ##args)
#define POSIX_INFO(fmt, args...) LogInfo(COMPONENT_TC_POSIX, fmt, ##args)
#define POSIX_DEBUG(fmt, args...) LogDebug(COMPONENT_TC_POSIX, fmt, ##args)

#ifdef __cplusplus
extern "C" {
#endif

void* posix_init(const char* config_file, const char* log_file);

tc_file* posix_open(const char *path, int flags, mode_t mode);

int posix_close(tc_file *file);

tc_file *posix_openv(const char **paths, int count, int *flags, mode_t *modes);

tc_res posix_closev(tc_file *files, int count);

off_t posix_fseek(tc_file *tcf, off_t offset, int whence);

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

tc_res posix_listdirv(const char **dirs, int count, struct tc_attrs_masks masks,
		      int max_entries, bool recursive, tc_listdirv_cb cb,
		      void *cbarg, bool istxn);

tc_res posix_mkdirv(struct tc_attrs *dirs, int count, bool is_transaction);

tc_res posix_copyv(struct tc_extent_pair *pairs, int count,
		   bool is_transaction);

tc_res posix_symlinkv(const char **oldpaths, const char **newpaths, int count,
		      bool istxn);

tc_res posix_readlinkv(const char **paths, char **bufs, size_t *bufsizes,
		       int count, bool istxn);

int posix_chdir(const char *path);

char *posix_getcwd();

#ifdef __cplusplus
}
#endif

#endif // __TC_IMPL_POSIX_H__
