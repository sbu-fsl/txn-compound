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
tc_file* nfs4_open(const char *path, int flags, mode_t mode);

/**
 * Open a list of files specified by paths
 *
 * Returns a list of tc_file that the caller is responsible for freeing.
 */
tc_file *nfs4_openv(const char **paths, int count, int *flags, mode_t *modes);

/*
 * @file - File that has to be closed
 *
 * Calls ktcclose with the right fh-stateid-seqid
 * If server is unreachable, might return failure
 */
int nfs4_close(tc_file *tcf);

/**
 *
 * On success, "tcfs" will be freed.
 */
tc_res nfs4_closev(tc_file *tcfs, int count);

off_t nfs4_fseek(tc_file *tcf, off_t offset, int whence);

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

tc_res nfs4_mkdirv(struct tc_attrs *dirs, int count, bool is_transaction);

tc_res nfs4_listdirv(const char **dirs, int count, struct tc_attrs_masks masks,
		     int max_entries, bool recursive, tc_listdirv_cb cb,
		     void *cbarg, bool is_transaction);

tc_res nfs4_copyv(struct tc_extent_pair *pairs, int count, bool is_transaction);

tc_res nfs4_symlinkv(const char **oldpaths, const char **newpaths, int count,
		     bool istxn);

tc_res nfs4_readlinkv(const char **paths, char **bufs, size_t *bufsizes,
		      int count, bool istxn);

int nfs4_chdir(const char *path);

char *nfs4_getcwd();

#ifdef __cplusplus
}
#endif

#endif // __TC_IMPL_NFS4_H__
