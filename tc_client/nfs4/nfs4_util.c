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

/**
 * Protects "fd_list", "free_fds", and "free_fds_top".
 * It also protects all free "struct tc_kfd".
 */
static pthread_mutex_t fd_list_lock = PTHREAD_MUTEX_INITIALIZER;

static struct tc_kfd fd_list[MAX_FD];

/**
 * A stack of free file descriptor, which is an index of fd_list.
 * "free_fds_top" is the stack top of "free_fds".
 */
static int free_fds[MAX_FD];
static int free_fds_top;

int init_fd()
{
        int r = 0;
	int i = 0;
        pthread_rwlockattr_t rwlock_attr;

        if ((r = pthread_rwlockattr_init(&rwlock_attr)) != 0) {
                return r;
        }

        pthread_mutex_lock(&fd_list_lock);
        free_fds_top = 0;
	while (i < MAX_FD) {
                r = pthread_rwlock_init(&fd_list[i].fd_lock, &rwlock_attr);
                if (r != 0) {
			pthread_mutex_unlock(&fd_list_lock);
                        return r;
		}
		free_fds[free_fds_top++] = i;
		fd_list[i].fd = -1;
		i++;
	}
        pthread_mutex_unlock(&fd_list_lock);

        return 0;
}

/* Helper function to get free count, to be called before sending open to server
 */
int get_freecount()
{
        int freecount = 0;
        pthread_mutex_lock(&fd_list_lock);
        freecount = free_fds_top;
        pthread_mutex_unlock(&fd_list_lock);
	return freecount;
}

int get_fd(stateid4 *stateid, nfs_fh4 *object)
{
	int cur_fd = -1;

        assert(stateid && object);
        pthread_mutex_lock(&fd_list_lock);
        if (free_fds_top <= 0) {
		pthread_mutex_unlock(&fd_list_lock);
		return -ENFILE;
        }
        cur_fd = free_fds[--free_fds_top];

	assert(fd_list[cur_fd].fd < 0);

	fd_list[cur_fd].fd = cur_fd + TC_FD_OFFSET;
	memcpy(&fd_list[cur_fd].stateid, stateid, sizeof(stateid4));

	fd_list[cur_fd].fh.nfs_fh4_val = malloc(object->nfs_fh4_len);

	memcpy(fd_list[cur_fd].fh.nfs_fh4_val, object->nfs_fh4_val,
	       object->nfs_fh4_len);
	fd_list[cur_fd].fh.nfs_fh4_len = object->nfs_fh4_len;

	fd_list[cur_fd].seqid = 0;
	fd_list[cur_fd].offset = 0;

        pthread_mutex_unlock(&fd_list_lock);

	return cur_fd + TC_FD_OFFSET;
}

struct tc_kfd *get_fd_struct(int fd, bool lock_for_write)
{
        struct tc_kfd *tcfd;

	fd -= TC_FD_OFFSET;
	if (fd < 0 || fd >= MAX_FD) {
		return NULL;
	}

        tcfd = fd_list + fd;

        pthread_rwlock_rdlock(&tcfd->fd_lock);
	if (tcfd->fd < 0 || tcfd->fd != fd + TC_FD_OFFSET) {
                /* not in use OR not valid */
	        pthread_rwlock_unlock(&tcfd->fd_lock);
                return NULL;
        }

        if (lock_for_write) {  /* upgrade lock */
                pthread_rwlock_unlock(&tcfd->fd_lock);
		pthread_rwlock_wrlock(&tcfd->fd_lock);
	}

	return tcfd;
}

int put_fd_struct(struct tc_kfd **tcfd)
{
        int r;

        if (!tcfd) {
                return -1;
        }
        r = pthread_rwlock_unlock(&(*tcfd)->fd_lock);
        *tcfd = NULL;

        return r;
}

int freefd(int fd)
{
        struct tc_kfd *tcfd;

        tcfd = get_fd_struct(fd, true);
        if (!tcfd) {
                return -EINVAL;
        }

	/* We have a valid fd that needs to be closed */
	tcfd->fd = -1; /* set to "not in use" */
	tcfd->seqid = 0;
	tcfd->offset = 0;
	free(tcfd->fh.nfs_fh4_val);
        tcfd->fh.nfs_fh4_val = NULL;
        put_fd_struct(&tcfd);

        pthread_mutex_lock(&fd_list_lock);
	free_fds[free_fds_top++] = fd - TC_FD_OFFSET;
        pthread_mutex_unlock(&fd_list_lock);

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
        struct tc_kfd *tcfd;
        seqid4 seqid;

        tcfd = get_fd_struct(fd, true);
        if (!tcfd) {
                return -EINVAL;
        }

	seqid = fd_list[fd].seqid++;
        put_fd_struct(&tcfd);

	return seqid;
}

int tc_for_each_fd(tcfd_processor p, void *args)
{
	int i;
	int rc = 0;

        pthread_mutex_lock(&fd_list_lock);
	for (i = 0; i < MAX_FD; ++i) {
                pthread_rwlock_wrlock(&fd_list[i].fd_lock);
		if (fd_list[i].fd > 0) {
			rc = p(fd_list + i, args);
			if (rc != 0) {
				pthread_rwlock_wrlock(&fd_list[i].fd_lock);
				break;
                        }
		}
                pthread_rwlock_wrlock(&fd_list[i].fd_lock);
	}
        pthread_mutex_unlock(&fd_list_lock);

	return rc;
}

