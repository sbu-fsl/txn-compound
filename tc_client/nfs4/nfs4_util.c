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

#include "nfs4_util.h"

#include <stdlib.h>

/* TODO: add lock */
static struct tc_kfd fd_list[MAX_FD];
static int free_fdlist[MAX_FD];
static int freelist_count, freelist_head, freelist_tail;

int init_fd()
{
	int i = 0;
	while (i < MAX_FD) {
		free_fdlist[i] = i;
		fd_list[i].fd = -1;
		i++;
	}

	freelist_count = MAX_FD;
	freelist_head = 0;
	freelist_tail = MAX_FD;
}

int getfdnum()
{
	if (freelist_count <= 0) {
		/* Add error log indicating fd exhaustion */
		return -1;
	}
	return free_fdlist[freelist_head++];
}

/* Helper function to get free count, to be called before sending open to server
 */
int get_freecount()
{
	return freelist_count;
}

int get_fd(stateid4 *stateid, nfs_fh4 *object)
{
	int cur_fd = -1;

	cur_fd = getfdnum();
	if (cur_fd < 0) {
		/* This is not possible because open call is sent to server only
		 * if freecount is greater than 0 */
		assert(0);
	}

	assert(fd_list[cur_fd].fd < 0);

	fd_list[cur_fd].fd = cur_fd + TC_FD_OFFSET;
	memcpy(&fd_list[cur_fd].stateid, stateid, sizeof(stateid4));

	fd_list[cur_fd].fh.nfs_fh4_val = malloc(object->nfs_fh4_len);

	memcpy(fd_list[cur_fd].fh.nfs_fh4_val, object->nfs_fh4_val,
	       object->nfs_fh4_len);
	fd_list[cur_fd].fh.nfs_fh4_len = object->nfs_fh4_len;

	fd_list[cur_fd].seqid = 0;
	fd_list[cur_fd].offset = 0;

	freelist_count -= 1;
	return cur_fd + TC_FD_OFFSET;
}

struct tc_kfd *get_fd_struct(int fd)
{
	assert(fd >= TC_FD_OFFSET);
	return fd_list + (fd - TC_FD_OFFSET);
}

int fd_in_use(int fd)
{
	fd -= TC_FD_OFFSET;
	if (fd < 0 || fd > MAX_FD) {
		return -1;
	}

	if (fd_list[fd].fd < 0) {
                return -1;
        }

	return 0;
}

int freefd(int fd)
{
	fd -= TC_FD_OFFSET;
	if (fd < 0 || fd > MAX_FD) {
		/* Maybe assert()?? */
		/* Add error logs too */
		return -1;
	}

	if (fd_in_use(fd) < 0) {
		/* Add error logs too */
		return -1;
	}

	if (fd_list[fd].fd != fd) {
		/* Add error logs too */
		/* Implementation mistake, client has nothing to do with this */
		assert(0);
	}

	/* We have a valid fd that needs to be closed */

	fd_list[fd].fd = -1;
	fd_list[fd].seqid = 0;
	fd_list[fd].offset = 0;
	free(fd_list[fd].fh.nfs_fh4_val);

	freelist_tail %= MAX_FD;
	free_fdlist[freelist_tail++] = fd;
	freelist_count += 1;

	return 0;
}

/*
 * Caller has performed an operation which changed the state of a lock,
 * eg:- OPEN, OPEN_CONFIRM, CLOSE, etc.
 * This should be called after calling the state changing operation to update seq id.
 * This should be called only if the operation succeeded
 */
int incr_seqid(int fd)
{
	fd -= TC_FD_OFFSET;
	if (fd < 0 || fd > MAX_FD) {
		/* Maybe assert()?? */
		/* Add error logs too */
		return -1;
	}

	if (fd_in_use(fd) < 0) {
		/* Add error logs too */
		return -1;
	}

	if (fd_list[fd].fd != fd) {
		/* Add error logs too */
		/* Implementation mistake, client has nothing to do with this */
		assert(0);
	}

	fd_list[fd].seqid++;
	return fd_list[fd].seqid;
}

int tc_for_each_fd(tcfd_processor p, void *args)
{
	int i;
	int rc;

	for (i = 0; i < MAX_FD; ++i) {
		if (fd_list[i].fd > 0) {
			rc = p(fd_list + i, args);
			if (rc != 0)
				return rc;
		}
	}

	return 0;
}

