/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) Panasas Inc., 2011
 * Author: Jim Lieb jlieb@panasas.com
 *
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * ------------- 
 */

/* file.c
 * File I/O methods for VFS module
 */

#include "config.h"

#include <assert.h>
#include "fsal.h"
#include "FSAL/access_check.h"
#include "fsal_convert.h"
#include <unistd.h>
#include <fcntl.h>
#include "FSAL/fsal_commonlib.h"
#include "cryptfs_methods.h"
#include "fsal_handle_syscalls.h"
#include "ctr_crypto.h"

extern struct next_ops next_ops;

/** cryptfs_open
 * called with appropriate locks taken at the cache inode level
 */

fsal_status_t cryptfs_open(struct fsal_obj_handle *obj_hdl,
			   const struct req_op_context *opctx,
			   fsal_openflags_t openflags)
{
	return next_ops.obj_ops->open(obj_hdl, opctx, openflags);
}

/* cryptfs_status
 * Let the caller peek into the file's open/close state.
 */

fsal_openflags_t cryptfs_status(struct fsal_obj_handle * obj_hdl)
{
	return next_ops.obj_ops->status(obj_hdl);
}

/* cryptfs_read
 * concurrency (locks) is managed in cache_inode_*
 */

fsal_status_t cryptfs_read(struct fsal_obj_handle * obj_hdl,
			   const struct req_op_context * opctx, uint64_t offset,
			   size_t buffer_size, void *buffer,
			   size_t * read_amount, bool * end_of_file)
{
	LogDebug(COMPONENT_FSAL, "buffer_size = %d", buffer_size);
	fsal_status_t ret = next_ops.obj_ops->read(obj_hdl, opctx, offset, buffer_size,
				      buffer, read_amount, end_of_file);

	if(FSAL_IS_ERROR(ret)) {
		return ret;
	}

	fsal_status_t retd = cryptfs_decrypt(offset, buffer_size, buffer);
	if(FSAL_IS_ERROR(retd)) {
		return retd;
	}

	return ret;
}

/* cryptfs_write
 * concurrency (locks) is managed in cache_inode_*
 */

fsal_status_t cryptfs_write(struct fsal_obj_handle * obj_hdl,
			    const struct req_op_context * opctx, uint64_t offset,
			    size_t buffer_size, void *buffer,
			    size_t * write_amount, bool * fsal_stable)
{
	LogDebug(COMPONENT_FSAL, "offset = %lu, buffer_size = %lu", offset, buffer_size);

	fsal_status_t ret = cryptfs_encrypt(offset, buffer_size, buffer);

	if(FSAL_IS_ERROR(ret)) {
		return ret;
	}

#if 0
	/* Encrypt - POC */
	char *byte = (char*)buffer;
	int count;
	for(count = 0; count < buffer_size; count ++) {
		*byte += 1;
		byte ++;
	}
#endif

	return next_ops.obj_ops->write(obj_hdl, opctx, offset, buffer_size,
				       buffer, write_amount, fsal_stable);
}

/* cryptfs_commit
 * Commit a file range to storage.
 * for right now, fsync will have to do.
 */

fsal_status_t cryptfs_commit(struct fsal_obj_handle * obj_hdl,	/* sync */
			     off_t offset, size_t len)
{
	return next_ops.obj_ops->commit(obj_hdl, offset, len);
}

/* cryptfs_lock_op
 * lock a region of the file
 * throw an error if the fd is not open.  The old fsal didn't
 * check this.
 */

fsal_status_t cryptfs_lock_op(struct fsal_obj_handle * obj_hdl,
			      const struct req_op_context * opctx, void *p_owner,
			      fsal_lock_op_t lock_op,
			      fsal_lock_param_t * request_lock,
			      fsal_lock_param_t * conflicting_lock)
{
	return next_ops.obj_ops->lock_op(obj_hdl, opctx, p_owner, lock_op,
					 request_lock, conflicting_lock);
}

/* cryptfs_close
 * Close the file if it is still open.
 * Yes, we ignor lock status.  Closing a file in POSIX
 * releases all locks but that is state and cache inode's problem.
 */

fsal_status_t cryptfs_close(struct fsal_obj_handle * obj_hdl)
{
	return next_ops.obj_ops->close(obj_hdl);
}

/* cryptfs_lru_cleanup
 * free non-essential resources at the request of cache inode's
 * LRU processing identifying this handle as stale enough for resource
 * trimming.
 */

fsal_status_t cryptfs_lru_cleanup(struct fsal_obj_handle * obj_hdl,
				  lru_actions_t requests)
{
	return next_ops.obj_ops->lru_cleanup(obj_hdl, requests);
}
