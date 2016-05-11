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

#include "splice_copy.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

ssize_t splice_copy_file(const char *src, size_t offset, size_t count,
			 const char *dst)
{
	int srcfd;
	int dstfd;
	ssize_t copied;
	struct stat st;

	srcfd = open(src, O_RDONLY);
	if (srcfd < 0) {
		return -errno;
	}
	if (count == 0) {
		if (fstat(srcfd, &st) < 0) {
			close(srcfd);
			return -errno;
		}
		count = st.st_size;
	}

	dstfd = open(dst, O_WRONLY | O_CREAT);
	if (dstfd < 0) {
		close(srcfd);
		return -errno;
	}

	copied = splice_fcopy(srcfd, offset, dstfd, 0, count);

	close(dstfd);
	close(srcfd);
	return copied;
}

ssize_t splice_copy(const char *src, size_t src_offset, const char *dst,
		    size_t dst_offset, size_t count)
{
	int srcfd;
	int dstfd;
	int copied;

	srcfd = open(src, O_RDONLY);
	if (srcfd < 0) {
		return -errno;
	}

	dstfd = open(dst, O_WRONLY | O_CREAT, 0755);
	if (dstfd < 0) {
		close(srcfd);
		return -errno;
	}

	copied = splice_fcopy(srcfd, src_offset, dstfd, dst_offset, count);

	close(dstfd);
	close(srcfd);
	return copied;
}

static inline size_t min(size_t a, size_t b) {
	return a < b ? a : b;
}

ssize_t splice_fcopy(int srcfd, size_t src_offset, int dstfd,
		     size_t dst_offset, size_t count)
{
	int pipefd[2];
	ssize_t n1;
	ssize_t n2;
	ssize_t copied = 0;
	size_t off1;
	size_t off2;

	if (pipe(pipefd) < 0) {
		return -errno;
	}

	while (copied < count) {
		off1 = src_offset;
		n1 = splice(srcfd, &off1, pipefd[1], NULL,
			    min(64 * 1024, count - copied),
			    SPLICE_F_MOVE | SPLICE_F_MORE);
		if (n1 < 0) {
			copied = -errno;
			goto out;
		}

		off2 = dst_offset;
		n2 = splice(pipefd[0], NULL, dstfd, &off2, n1,
			    SPLICE_F_MOVE | SPLICE_F_MORE);
		if (n2 < 0) {
			copied = -errno;
			goto out;
		}

		src_offset += n2;
		dst_offset += n2;
		copied += n2;
	}

out:
	close(pipefd[0]);
	close(pipefd[1]);
	return copied;
}
