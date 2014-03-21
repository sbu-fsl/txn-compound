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
#include "secnfs_methods.h"
#include "fsal_handle_syscalls.h"
#include "secnfs.h"

extern struct next_ops next_ops;

static bool should_read_keyfile(const struct secnfs_fsal_obj_handle *hdl)
{
        return hdl->obj_handle.type == REGULAR_FILE
                && hdl->obj_handle.attributes.filesize > 0
                && !hdl->key_initialized;
}


/** secnfs_open
 * called with appropriate locks taken at the cache inode level
 */
fsal_status_t secnfs_open(struct fsal_obj_handle *obj_hdl,
                          const struct req_op_context *opctx,
                          fsal_openflags_t openflags)
{
        struct secnfs_fsal_obj_handle *hdl = secnfs_handle(obj_hdl);
        fsal_status_t st;

        st = next_ops.obj_ops->open(hdl->next_handle, opctx, openflags);

        if (!FSAL_IS_ERROR(st) && should_read_keyfile(hdl)) {
                // read file key and iv
                st = read_keyfile(obj_hdl, opctx);
        }

        return st;
}


/* secnfs_status
 * Let the caller peek into the file's open/close state.
 */
fsal_openflags_t secnfs_status(struct fsal_obj_handle *obj_hdl)
{
	return next_ops.obj_ops->status(next_handle(obj_hdl));
}


inline fsal_status_t secnfs_to_fsal_status(secnfs_s s) {
        fsal_status_t fsal_s;

        if (s == SECNFS_OKAY) {
                fsal_s.major = ERR_FSAL_NO_ERROR;
                fsal_s.minor = 0;
        } else {
                fsal_s.major = ERR_FSAL_IO;
                fsal_s.minor = s;
        }

        return fsal_s;
}


/*
 * concurrency (locks) is managed in cache_inode_*
 */
fsal_status_t secnfs_read(struct fsal_obj_handle *obj_hdl,
			  const struct req_op_context *opctx, uint64_t offset,
			  size_t buffer_size, void *buffer,
			  size_t *read_amount, bool *end_of_file)
{
        struct secnfs_fsal_obj_handle *hdl = secnfs_handle(obj_hdl);
        fsal_status_t st;
        uint64_t next_offset;

	LogDebug(COMPONENT_FSAL, "buffer_size = %d", buffer_size);

        next_offset = obj_hdl->type == REGULAR_FILE
                        ? offset + KEY_FILE_SIZE
                        : offset;

        st = next_ops.obj_ops->read(hdl->next_handle, opctx,
                                    next_offset,
                                    buffer_size, buffer,
                                    read_amount, end_of_file);
        if (FSAL_IS_ERROR(st)) {
                return st;
        }

        if (obj_hdl->type == REGULAR_FILE) {
                assert(hdl->key_initialized);
                // TODO only decrypt "*read_amount"
                secnfs_s retd = secnfs_decrypt(hdl->fk, hdl->iv, offset,
                                               buffer_size, buffer, buffer);
                st = secnfs_to_fsal_status(retd);
        }

	return st;
}

/* secnfs_write
 * concurrency (locks) is managed in cache_inode_*
 */

fsal_status_t secnfs_write(struct fsal_obj_handle *obj_hdl,
			   const struct req_op_context *opctx, uint64_t offset,
			   size_t buffer_size, void *buffer,
			   size_t *write_amount, bool *fsal_stable)
{
        struct secnfs_fsal_obj_handle *hdl = secnfs_handle(obj_hdl);
        uint64_t next_offset = offset;

        if (obj_hdl->type == REGULAR_FILE) {
                next_offset += KEY_FILE_SIZE;
                assert(hdl->key_initialized);
                secnfs_s ret = secnfs_encrypt(hdl->fk,
                                              hdl->iv,
                                              offset,
                                              buffer_size,
                                              buffer,
                                              buffer);
                if(ret != SECNFS_OKAY) {
                        return secnfs_to_fsal_status(ret);
                }
        }

	return next_ops.obj_ops->write(next_handle(obj_hdl), opctx,
                                       next_offset,
                                       buffer_size, buffer, write_amount,
                                       fsal_stable);
}


/* secnfs_commit
 * Commit a file range to storage.
 * for right now, fsync will have to do.
 */
fsal_status_t secnfs_commit(struct fsal_obj_handle *obj_hdl,	/* sync */
			    off_t offset, size_t len)
{
	return next_ops.obj_ops->commit(next_handle(obj_hdl), offset, len);
}


/* secnfs_lock_op
 * lock a region of the file
 * throw an error if the fd is not open.  The old fsal didn't
 * check this.
 */
fsal_status_t secnfs_lock_op(struct fsal_obj_handle *obj_hdl,
			     const struct req_op_context *opctx, void *p_owner,
			     fsal_lock_op_t lock_op,
			     fsal_lock_param_t *request_lock,
			     fsal_lock_param_t *conflicting_lock)
{
        return next_ops.obj_ops->lock_op(next_handle(obj_hdl), opctx, p_owner,
                                         lock_op, request_lock,
                                         conflicting_lock);
}


/* secnfs_close
 * Close the file if it is still open.
 * Yes, we ignor lock status.  Closing a file in POSIX
 * releases all locks but that is state and cache inode's problem.
 */
fsal_status_t secnfs_close(struct fsal_obj_handle *obj_hdl)
{
	return next_ops.obj_ops->close(next_handle(obj_hdl));
}


/* secnfs_lru_cleanup
 * free non-essential resources at the request of cache inode's
 * LRU processing identifying this handle as stale enough for resource
 * trimming.
 */
fsal_status_t secnfs_lru_cleanup(struct fsal_obj_handle *obj_hdl,
				 lru_actions_t requests)
{
	return next_ops.obj_ops->lru_cleanup(next_handle(obj_hdl), requests);
}
