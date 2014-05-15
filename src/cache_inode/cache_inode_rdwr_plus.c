/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright CEA/DAM/DIF  (2008)
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *
 * Copyright Stony Brook University, 2014
 * by Ming Chen <v.mingchen@gmail.com>
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
 *
 * ---------------------------------------
 */

/**
 * @addtogroup cache_inode
 * @{
 */

/**
 * @file cache_inode_rdwr.c
 * @brief Performs I/O on regular files
 */

#include "config.h"
#include "fsal.h"

#include "log.h"
#include "hashtable.h"
#include "cache_inode.h"
#include "cache_inode_lru.h"
#include "nfs_core.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <time.h>
#include <pthread.h>
#include <assert.h>

static cache_inode_status_t close_entry(cache_entry_t *entry, int flags)
{
	cache_inode_status_t cstatus;

	LogFullDebug(COMPONENT_CACHE_INODE,
		     "cache_inode_rdwr_plus: CLOSING entry %p", entry);
	PTHREAD_RWLOCK_unlock(&entry->content_lock);
	PTHREAD_RWLOCK_wrlock(&entry->content_lock);

	cstatus = cache_inode_close(entry, flags);

	if (cstatus != CACHE_INODE_SUCCESS) {
		LogCrit(COMPONENT_CACHE_INODE,
			"Error closing file in cache_inode_rdwr_plus: %d",
			cstatus);
	}

	return cstatus;
}

/**
 * @brief Reads/Writes through the cache layer (plus)
 *
 * This function performs I/O, either using the Ganesha in-memory or
 * disk cache or through the FSAL directly.  The caller MUST NOT hold
 * either the content or attribute locks when calling this function.
 *
 * @param[in]     entry        File to be read or written
 * @param[in]     io_direction Whether this is a read or a write
 * @param[in]     offset       Absolute file position for I/O
 * @param[in]     io_size      Amount of data to be read or written
 * @param[out]    bytes_moved  The length of data successfuly read or written
 * @param[in,out] buffer [DEPRECATED] Where in memory to read or write data
 * @param[in,out] data_plus    Extra data including protection information etc.
 * @param[out]    eof          Whether a READ encountered the end of file.  May
 *                             be NULL for writes.
 * @param[in]     req_ctx      FSAL credentials
 * @param[in]     sync         Whether the write is synchronous or not
 *
 * @return CACHE_INODE_SUCCESS or various errors
 */

cache_inode_status_t
cache_inode_rdwr_plus(cache_entry_t *entry,
		      cache_inode_io_direction_t io_direction,
		      uint64_t offset, size_t io_size,
		      size_t *bytes_moved, void *buffer,
		      struct data_plus *data_plus, bool *eof,
		      struct req_op_context *req_ctx, bool *sync)
{
	/* Error return from FSAL calls */
	fsal_status_t fsal_status = { 0, 0 };
	struct fsal_obj_handle *obj_hdl = entry->obj_handle;
	/* Required open mode to have O_DIRECT set */
	fsal_openflags_t openflags = FSAL_O_DIRECT;
	fsal_openflags_t loflags;
	/* True if we have taken the content lock on 'entry' */
	bool content_locked = false;
	/* True if we have taken the attribute lock on 'entry' */
	bool attributes_locked = false;
	/* TRUE if we opened a previously closed FD */
	bool opened = false;

	cache_inode_status_t status = CACHE_INODE_SUCCESS;

	/* Set flags for a read or write, as appropriate */
	if (io_direction == CACHE_INODE_READ_PLUS) {
		openflags |= FSAL_O_READ;
	} else {
		assert(io_direction == CACHE_INODE_WRITE_PLUS);
		if (!*sync) {
			LogMajor(COMPONENT_FSAL, "sync should be set for "
				 "CACHE_INODE_WRITE_PLUS");
			return CACHE_INODE_INVALID_ARGUMENT;
		}
		openflags |= FSAL_O_WRITE;
		openflags |= FSAL_O_SYNC;
	}

	assert(obj_hdl != NULL);

	/* IO is done only on REGULAR_FILEs */
	if (entry->type != REGULAR_FILE) {
		status =
		    entry->type ==
		    DIRECTORY ? CACHE_INODE_IS_A_DIRECTORY :
		    CACHE_INODE_BAD_TYPE;
		goto out;
	}

	/* Check open flags; (re)open with desired flags if necessary. */
	PTHREAD_RWLOCK_rdlock(&entry->content_lock);
	content_locked = true;
	do {
		loflags = obj_hdl->ops->status(obj_hdl);

		if (is_open(entry) && (loflags & openflags) == openflags)
			break;

		PTHREAD_RWLOCK_unlock(&entry->content_lock);
		PTHREAD_RWLOCK_wrlock(&entry->content_lock);
		status = cache_inode_open(entry, openflags, req_ctx,
					  (CACHE_INODE_FLAG_CONTENT_HAVE |
					   CACHE_INODE_FLAG_CONTENT_HOLD));
		PTHREAD_RWLOCK_unlock(&entry->content_lock);
		PTHREAD_RWLOCK_rdlock(&entry->content_lock);

		if (status != CACHE_INODE_SUCCESS)
			goto out;

		opened = true;
	} while (true);

	/* Call FSAL_read_plus or FSAL_write_plus */
	if (io_direction == CACHE_INODE_READ_PLUS) {
		fsal_status =
		    obj_hdl->ops->read_plus(obj_hdl, req_ctx, offset, io_size,
					    buffer, bytes_moved, data_plus,
					    eof);
	} else {
		fsal_status =
		    obj_hdl->ops->write_plus(obj_hdl, req_ctx, offset, io_size,
					     buffer, bytes_moved, data_plus,
					     sync);

		if (!FSAL_IS_ERROR(fsal_status) && !*sync) {
			LogMajor(COMPONENT_FSAL,
				 "write_plus returns without sync set.");
			status = CACHE_INODE_SERVERFAULT;
			goto out;
		}
	}

	LogFullDebug(COMPONENT_FSAL,
		     "cache_inode_rdwr_plus: FSAL IO operation returned "
		     "%d, asked_size=%zu, effective_size=%zu",
		     fsal_status.major, io_size, *bytes_moved);

	if (FSAL_IS_ERROR(fsal_status)) {
		if (fsal_status.major == ERR_FSAL_DELAY) {
			LogEvent(COMPONENT_CACHE_INODE,
				 "cache_inode_rdwr_plus: FSAL_write "
				 " returned EBUSY");
		} else {
			LogDebug(COMPONENT_CACHE_INODE,
				 "cache_inode_rdwr_plus: fsal_status.major = %d",
				 fsal_status.major);
		}

		*bytes_moved = 0;
		status = cache_inode_error_convert(fsal_status);

		if (fsal_status.major == ERR_FSAL_STALE) {
			cache_inode_kill_entry(entry);
			goto out;
		}

		if ((fsal_status.major != ERR_FSAL_NOT_OPENED)
		    && (obj_hdl->ops->status(obj_hdl) != FSAL_O_CLOSED)) {
			close_entry(entry, (CACHE_INODE_FLAG_REALLYCLOSE |
					    CACHE_INODE_FLAG_CONTENT_HAVE |
					    CACHE_INODE_FLAG_CONTENT_HOLD));
		}

		goto out;
	}

	LogFullDebug(COMPONENT_CACHE_INODE,
		     "cache_inode_rdwr_plus: inode/direct: io_size=%zu, "
		     "bytes_moved=%zu, offset=%" PRIu64, io_size, *bytes_moved,
		     offset);

	if (opened) {
		status = close_entry(entry, (CACHE_INODE_FLAG_CONTENT_HAVE |
					     CACHE_INODE_FLAG_CONTENT_HOLD));
		if (status != CACHE_INODE_SUCCESS)
			goto out;
	}

	if (content_locked) {
		PTHREAD_RWLOCK_unlock(&entry->content_lock);
		content_locked = false;
	}

	PTHREAD_RWLOCK_wrlock(&entry->attr_lock);
	attributes_locked = true;
	if (io_direction == CACHE_INODE_WRITE_PLUS) {
		status = cache_inode_refresh_attrs(entry, req_ctx);
		if (status != CACHE_INODE_SUCCESS)
			goto out;
	} else {
		cache_inode_set_time_current(&obj_hdl->attributes.atime);
	}
	PTHREAD_RWLOCK_unlock(&entry->attr_lock);
	attributes_locked = false;

	status = CACHE_INODE_SUCCESS;

 out:

	if (content_locked) {
		PTHREAD_RWLOCK_unlock(&entry->content_lock);
		content_locked = false;
	}

	if (attributes_locked) {
		PTHREAD_RWLOCK_unlock(&entry->attr_lock);
		attributes_locked = false;
	}

	return status;
}

/** @} */
