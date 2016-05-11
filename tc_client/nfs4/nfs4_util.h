/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) Stony Brook University 2016
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* Header file for implementing tc features */

#ifndef __TC_NFS4_UTIL_H__
#define __TC_NFS4_UTIL_H__

#include "export_mgr.h"
#include "tc_impl_nfs4.h"
#include <fcntl.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Structure to be passed to ktcread
 * user_arg - Contains file-path, user buffer, read length, offset, etc
 * which are passed by the user
 */
struct tcread_kargs
{
	struct tc_iovec *user_arg;
	char *path;
	stateid4 *sid;
	nfs_fh4 *fh;
	OPEN4resok *opok_handle;
	struct attrlist attrib;
};

/*
 * Structure to be passed to ktcwrite
 * user_arg - Contains file-path, user buffer, write length, offset, etc
 * which are passed by the user
 */
struct tcwrite_kargs
{
	struct tc_iovec *user_arg;
	char *path;
	stateid4 *sid;
	nfs_fh4 *fh;
	OPEN4resok *opok_handle;
	struct attrlist attrib;
};

struct tcopen_kargs
{
	char *path;
	OPEN4resok *opok_handle;
	GETFH4resok *fhok_handle;
	struct attrlist attrib;
};

#define MAX_READ_COUNT      10
#define MAX_WRITE_COUNT     10
#define MAX_DIR_DEPTH       10
#define MAX_FILENAME_LENGTH 256
#define MAX_FD              1024
#define TC_FD_OFFSET	    (1 << 30)

struct tc_kfd
{
        pthread_rwlock_t fd_lock;
	int fd; /* fd might not be needed because we will be indexing using
		   array index, so this will be used only to check if an fd is
		   being used. So has to be set to -1 if freed  */
	nfs_fh4 fh;
	/* Export id not needed now, might be needed in future */
	stateid4 stateid;
	/* seqid is per lock owner, ktcopen creates a new owner for every open,
	 * so start with 1 */
	seqid4 seqid;
	int offset;
        size_t filesize;
};

int init_fd();

/* Helper function to get free count, to be called before sending open to server
 */
int get_freecount();

int get_fd(stateid4 *stateid, nfs_fh4 *object);

int freefd(int fd);

/*
 * Caller has performed an operation which changed the state of a lock,
 * eg:- OPEN, OPEN_CONFIRM, CLOSE, etc.
 * This should be called after calling the state changing operation to update seq id.
 * This should be called only if the operation succeeded
 */
int incr_seqid(int fd);

/**
 * Get and lock "struct tc_kfd" corresponding to "fd".
 */
struct tc_kfd *get_fd_struct(int fd, bool lock_for_write);

/**
 * Release lock on specified "*tcfd".  "*tcfd" will be set to NULL on success.
 */
int put_fd_struct(struct tc_kfd **tcfd);

/**
 * tcfd_processor will be called with the "tcfd->fd_lock" hold for write.
 */
typedef int (*tcfd_processor)(struct tc_kfd *tcfd, void *args);

int tc_for_each_fd(tcfd_processor p, void *args);

bool readdir_reply(const char *name, void *dir_state, fsal_cookie_t cookie);

#ifdef __cplusplus
}
#endif


#endif // __TC_NFS4_UTIL_H__
