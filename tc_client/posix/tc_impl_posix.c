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

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <assert.h>
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <sys/types.h>

#include "tc_impl_posix.h"
#include "tc_helper.h"
#include "log.h"
#include "splice_copy.h"

/*
 * open routine for POSIX files
 * path - file path
 * flags - open flags
 */

void* posix_init(const char* config_file, const char* log_file) {
	SetNamePgm("TC-POSIX");
	SetNameFunction("posix");
	SetNameHost("localhost");
	init_logging(log_file, NIV_EVENT);
	return NULL;
}

tc_file *posix_openv(const char **paths, int count, int *flags, mode_t *modes)
{
	tc_file *tcfs;
	int fd;
	int i;

	tcfs = calloc(count, sizeof(*tcfs));
	if (tcfs) {
		for (i = 0; i < count; ++i) {
			tcfs[i].type = TC_FILE_DESCRIPTOR;
			fd = open(paths[i], flags[i], modes[i]);
			tcfs[i].fd = fd >= 0 ? fd : -errno;
		}
	}

	return tcfs;
}

tc_file *posix_open(const char *path, int flags, mode_t mode)
{
	return posix_openv(&path, 1, &flags, &mode);
}

tc_res posix_closev(tc_file *tcfs, int count)
{
	int i;
	tc_res tcres = { .okay = true };

	for (i = 0; i < count; ++i) {
		assert(tcfs[i].type == TC_FILE_DESCRIPTOR);
		/* return error no in case of failure */
		if (close(tcfs[i].fd) < 0) {
			tcres.okay = false;
			tcres.index = i;
			tcres.err_no = errno;
			break;
		} else {
			tcfs[i].fd = INT_MIN;
		}
	}

	if (tcres.okay) {
		free(tcfs);
	}

	return tcres;
}

/*
 * close routine for POSIX files
 * file - tc_file structure with file
 * descriptor value.
 */
int posix_close(tc_file *tcf)
{
	tc_res tcres;
	tcres = posix_closev(tcf, 1);
	if (tcres.okay) {
		free(tcf);
		return 0;
	} else {
		return -tcres.err_no;
	}
}

off_t posix_fseek(tc_file *tcf, off_t offset, int whence)
{
	assert(tcf->type == TC_FILE_DESCRIPTOR);
	return lseek(tcf->fd, offset, whence);
}

static int posix_stat(const tc_file *tcf, struct stat *st)
{
	int rc;
	if (tcf->type == TC_FILE_PATH) {
		rc = stat(tcf->path, st);
	} else if (tcf->type == TC_FILE_DESCRIPTOR) {
		rc = fstat(tcf->fd, st);
	} else {
		rc = -1;
	}
	return rc;
}

/*
 * arg - Array of reads for one or more files
 *       Contains file-path, read length, offset, etc.
 * read_count - Length of the above array
 *              (Or number of reads)
 */
tc_res posix_readv(struct tc_iovec *arg, int read_count, bool is_transaction)
{
	int fd, i = 0;
	ssize_t amount_read;
	tc_file file = { 0 };
	struct tc_iovec *iov = NULL;
	tc_res result = { .okay = true, .index = -1, .err_no = 0 };
	struct stat st;

	POSIX_WARN("posix_readv() called \n");

	for (i = 0; i < read_count; ++i) {
		iov = arg + i;
		/*
		 * if the user specified the path and not file descriptor
		 * then call open to obtain the file descriptor else
		 * go ahead with the file descriptor specified by the user
		 */
		if (iov->file.type == TC_FILE_PATH) {
			fd = open(iov->file.path, O_RDONLY);
		} else if (iov->file.type == TC_FILE_DESCRIPTOR) {
			fd = iov->file.fd;
		} else {
			POSIX_ERR("unsupported type: %d", iov->file.type);
		}

		if (fd < 0) {
			result.okay = false;
			POSIX_ERR("failed in readv: %s\n", strerror(errno));
			break;
		}

		/* Read data */
		if (iov->offset == TC_OFFSET_CUR) {
			amount_read = read(fd, iov->data, iov->length);
		} else {
			amount_read =
			    pread(fd, iov->data, iov->length, iov->offset);
		}
		if (amount_read < 0) {
			if (iov->file.type == TC_FILE_PATH) {
				close(fd);
			}
			result.okay = false;
			break;
		}

		/* set the length to number of bytes successfully read */
		iov->length = amount_read;

		if (fstat(fd, &st) != 0) {
			POSIX_ERR("failed to stat file");
			result = tc_failure(i, errno);
			break;
		}

		if (iov->offset == TC_OFFSET_CUR) {
			iov->is_eof = lseek(fd, 0, SEEK_CUR) == st.st_size;
		} else {
			iov->is_eof = (iov->offset + iov->length) == st.st_size;
		}

		if (iov->file.type == TC_FILE_PATH && close(fd) < 0) {
			result.okay = false;
			break;
		}
	}

	/* No error encountered */
	if (result.okay)
		goto exit;

	result.index = i;
	result.err_no = errno;

	POSIX_WARN("posix_readv() failed at index : %d\n", result.index);

exit:
	return result;
}

/*
 * arg - Array of writes for one or more files
 *       Contains file-path, write length, offset, etc.
 * read_count - Length of the above array
 *              (Or number of reads)
 */
tc_res posix_writev(struct tc_iovec *arg, int write_count, bool is_transaction)
{
	int fd, i = 0;
	ssize_t written = 0;
	struct tc_iovec *iov = NULL;
	tc_res result = { .okay = true, .index = -1, .err_no = 0 };
	int flags;
	off_t offset;

	POSIX_WARN("posix_writev() called \n");

	for (i = 0; i < write_count; ++i) {
		iov = arg + i;

		/* open the requested file */
		flags = O_WRONLY;
		if (iov->is_creation) {	/* create */
			flags |= O_CREAT;
		}

		if (iov->file.type == TC_FILE_PATH) {
			fd = open(iov->file.path, flags);
		} else if (iov->file.type == TC_FILE_DESCRIPTOR) {
			fd = iov->file.fd;
		} else {
			POSIX_ERR("unsupported type: %d", iov->file.type);
		}

		if (fd < 0) {
			result.okay = false;
			result.err_no = errno;
			break;
		}

		offset = iov->offset;
		/* append */
		if (offset == TC_OFFSET_END) {
			offset = lseek(fd, 0, SEEK_END);
		}

		/* Write data */
		if (iov->length > 0) {
			if (offset == TC_OFFSET_CUR) {
				written = write(fd, iov->data, iov->length);
			} else {
				written =
				    pwrite(fd, iov->data, iov->length, offset);
			}

			if (written < 0) {
				if (iov->file.type == TC_FILE_PATH) {
					close(fd);
				}
				result.okay = false;
				break;
			}
		}

		/* set the length to number of bytes successfully written */
		iov->length = written;
		if (iov->file.type == TC_FILE_PATH && close(fd) < 0) {
			result.okay = false;
			break;
		}
	}

	/* No errors encountered */
	if (result.okay)
		goto exit;

	/* Set the index at which error occured and the error no */
	result.index = i;
	result.err_no = errno;

	POSIX_WARN("posix_writev() failed at index : %d\n", result.index);

exit:
	return result;
}

/*
 * Copy the struct stat to tc_attrs
 *
 * @st - stat structure
 * @attr_obj - tc_attrs object to be filled with the
 * stats structure values
 */
void copy_attrs(const struct stat *st, struct tc_attrs *attr_obj)
{
	if (attr_obj->masks.has_mode)
		attr_obj->mode = st->st_mode;

	if (attr_obj->masks.has_size)
		attr_obj->size = st->st_size;

	if (attr_obj->masks.has_nlink)
		attr_obj->nlink = st->st_nlink;

	if (attr_obj->masks.has_uid)
		attr_obj->uid = st->st_uid;

	if (attr_obj->masks.has_gid)
		attr_obj->gid = st->st_gid;

	if (attr_obj->masks.has_rdev)
		attr_obj->rdev = st->st_rdev;

	if (attr_obj->masks.has_atime) {
		attr_obj->atime.tv_sec = st->st_atime;
		attr_obj->atime.tv_nsec = 0;
	}

	if (attr_obj->masks.has_mtime) {
		attr_obj->mtime.tv_sec = st->st_mtime;
		attr_obj->mtime.tv_nsec = 0;
	}

	if (attr_obj->masks.has_ctime) {
		attr_obj->ctime.tv_sec = st->st_ctime;
		attr_obj->ctime.tv_nsec = 0;
	}
}

/**
 * Get attributes of files
 *
 * @attrs: array of attributes to get
 * @count: the count of tc_attrs in the preceding array
 * @is_transaction: whether to execute the compound as a transaction
 */

tc_res posix_getattrsv(struct tc_attrs *attrs, int count, bool is_transaction)
{
	int fd = -1, i = 0, res = 0;
	struct tc_attrs *cur_attr = NULL;
	tc_res result = { .okay = true, .index = -1, .err_no = 0 };
	struct stat st;

	POSIX_WARN("posix_getattrsv() called \n");

	while (i < count) {
		cur_attr = attrs + i;

		/* get attributes */
		if (cur_attr->file.type == TC_FILE_PATH)
			res = stat(cur_attr->file.path, &st);
		else
			res = fstat(cur_attr->file.fd, &st);

		if (res < 0) {
			perror("");
			POSIX_WARN("file path : %s\n", cur_attr->file.path);
			result.okay = false;
			result.err_no = errno;
			result.index = i;
			POSIX_WARN("posix_getattrsv() failed at index : %d\n",
				   result.index);
			break;
		}

		/* copy stat output */
		copy_attrs(&st, cur_attr);

		i++;
	}

	return result;
}

static int helper_set_attrs(struct tc_attrs *attrs)
{
	int res = 0;
	struct stat s;
	struct timeval times[2] = {};

	/* check if nlink bit is set, if set return with error */
	if (attrs->masks.has_nlink) {
		POSIX_WARN("set_attrs() failed : nlink attribute bit"
			   " should not be set \n");
		return -1;
	}

	/* check if rdev bit is set, if set return with error */
	if (attrs->masks.has_rdev) {
		POSIX_WARN("set_attrs() failed : rdev attribute bit"
			   " should not be set \n");
		return -1;
	}

	/* set the mode */
	if (attrs->masks.has_mode) {
		if (attrs->file.type == TC_FILE_PATH)
			res = chmod(attrs->file.path, attrs->mode);
		else
			res = fchmod(attrs->file.fd, attrs->mode);

		if (res < 0)
			goto exit;
	}

	/* set the file size */
	if (attrs->masks.has_size) {
		if (attrs->file.type == TC_FILE_PATH)
			res = truncate(attrs->file.path, attrs->size);
		else
			res = ftruncate(attrs->file.fd, attrs->size);

		if (res < 0)
			goto exit;
	}

	/* set the UID and GID */
	if (attrs->masks.has_uid || attrs->masks.has_gid) {

		if (attrs->file.type == TC_FILE_PATH)
			res = chown(attrs->file.path, attrs->uid, attrs->gid);
		else
			res = fchown(attrs->file.fd, attrs->uid, attrs->gid);

		if (res < 0)
			goto exit;
	}

	/* set the atime and mtime */
	if (attrs->masks.has_atime || attrs->masks.has_mtime) {

		if (attrs->file.type == TC_FILE_PATH)
			stat(attrs->file.path, &s);
		else
			fstat(attrs->file.fd, &s);

		times[0].tv_sec = s.st_atime;
		times[1].tv_sec = s.st_mtime;

		if (attrs->masks.has_atime)
			TIMESPEC_TO_TIMEVAL(&times[0], &attrs->atime);

		if (attrs->masks.has_mtime)
			TIMEVAL_TO_TIMESPEC(&times[1], &attrs->mtime);

		if (attrs->file.type == TC_FILE_PATH)
			res = utimes(attrs->file.path, times);
		else
			res = futimes(attrs->file.fd, times);

		if (res < 0)
			goto exit;
	}

exit:
	return res;
}

/**
 * Set attributes of files.
 *
 * @attrs: array of attributes to set
 * @count: the count of tc_attrs in the preceding array
 * @is_transaction: whether to execute the compound as a transaction
 */
tc_res posix_setattrsv(struct tc_attrs *attrs, int count, bool is_transaction)
{
	int fd = -1, i = 0;
	struct tc_attrs *cur_attr = NULL;
	tc_res result = { .okay = true, .index = -1, .err_no = 0 };

	POSIX_WARN("posix_setattrsv() called \n");

	while (i < count) {
		cur_attr = attrs + i;

		/*
		 * Set the attributes if corrseponding mask bit is set
		 */
		if (helper_set_attrs(cur_attr) < 0) {
			result.okay = false;
			result.err_no = errno;
			result.index = i;
			POSIX_WARN("posix_setattrsv() failed at index : %d\n",
				   result.index);
			break;
		}

		i++;
	}

	return result;
}

/*
 * Rename File(s)
 *
 * @pairs[IN] - tc_file_pair structure containing the
 * old and new path of the file
 * @count[IN]: the count of tc_file_pair in the preceding array
 * @is_transaction[IN]: whether to execute the compound as a transaction
 */

tc_res posix_renamev(struct tc_file_pair *pairs, int count, bool is_transaction)
{
	int i = 0;
	tc_file_pair *cur_pair = NULL;
	tc_res result = { .okay = true, .index = -1, .err_no = 0 };

	while (i < count) {
		cur_pair = pairs + i;

		assert(cur_pair->src_file.type == TC_FILE_PATH &&
		       cur_pair->dst_file.type == TC_FILE_PATH &&
		       cur_pair->src_file.path != NULL &&
		       cur_pair->src_file.path != NULL);

		if (rename(cur_pair->src_file.path, cur_pair->dst_file.path) <
		    0) {
			perror("");
			result.okay = false;
			result.err_no = errno;
			result.index = i;

			POSIX_WARN("posix_renamev() failed at index : %d\n",
				   result.index);

			return result;
		}

		i++;
	}

	return result;
}

/*
 * Remove File(s)
 *
 * @files[IN] - tc_file structure containing the
 * path of the directory to be removed
 * @count[IN]: the count of tc_target_file in the preceding array
 * @is_transaction[IN]: whether to execute the compound as a transaction
 */

tc_res posix_removev(tc_file *files, int count, bool is_transaction)
{
	int i = 0;
	tc_file *cur_file = NULL;
	tc_res result = { .okay = true, .index = -1, .err_no = 0 };

	while (i < count) {
		cur_file = files + i;

		assert(cur_file->path != NULL);

		if (remove(cur_file->path) < 0) {
			result.okay = false;
			result.err_no = errno;
			result.index = i;

			POSIX_WARN("posix_removev() failed at index %d for "
				   "path %s: %s\n",
				   result.index, cur_file->path,
				   strerror(errno));

			return result;
		}

		i++;
	}

	return result;
}

/*
 * Remove Directory
 *
 * @dir[IN] - tc_file structure containing the
 * path of the directory to be removed
 * @count: the count of tc_target_file in the preceding array
 * @is_transaction: whether to execute the compound as a transaction
 */

tc_res posix_remove_dirv(tc_file *dir, int count, bool is_transaction)
{
	int i = 0;
	tc_file *cur_dir = NULL;
	tc_res result = { .okay = true, .index = -1, .err_no = 0 };

	while (i < count) {
		cur_dir = dir + i;

		assert(cur_dir->path != NULL);

		if (rmdir(cur_dir->path) < 0) {
			result.okay = false;
			result.err_no = errno;
			result.index = i;

			POSIX_WARN("posix_remove_dirv() failed at index : %d\n",
				   result.index);

			return result;
		}

		i++;
	}

	return result;
}

/*
 * Create Directory
 *
 * @dir[IN] - tc_file structure containing the
 * path of the directory to be created
 * @count: the count of tc_target_file in the preceding array
 * @is_transaction: whether to execute the compound as a transaction
 */

tc_res posix_mkdirv(struct tc_attrs *dirs, int count, bool is_transaction)
{
	int i = 0;
	tc_file *cur_dir = NULL;
	tc_res result = { .okay = true, .index = -1, .err_no = 0 };

	while (i < count) {
		cur_dir = &dirs[i].file;

		assert(cur_dir->path != NULL);

		if (mkdir(cur_dir->path, dirs[i].mode) < 0) {
			perror("");
			result.okay = false;
			result.err_no = errno;
			result.index = i;

			POSIX_WARN("posix_mkdirv() failed at index : %d\n",
				   result.index);

			return result;
		}

		i++;
	}

	return result;
}

/**
 * List the content of a directory.
 *
 * @dir [IN]: the path of the directory to list
 * @masks [IN]: masks of attributes to get for listed objects
 * @max_count [IN]: the maximum number of count to list
 * @contents [OUT]: the pointer to the array of files/directories in the
 * directory.  The array and the paths in the array will be allocated
 * internally by this function; the caller is responsible for releasing the
 * memory, probably by using tc_free_attrs().
 */

tc_res posix_listdir(const char *dir, struct tc_attrs_masks masks,
		     int max_count, struct tc_attrs **contents, int *count)
{
	DIR *dir_fd;
	struct tc_attrs *cur_attr = NULL;
	struct dirent *dp;
	tc_res result = { .okay = true, .index = -1, .err_no = 0 };
	char file_name[PATH_MAX];

	assert(dir != NULL);
	*contents = calloc(max_count, sizeof(struct tc_attrs));

	dir_fd = opendir(dir);

	if (!dir_fd) {
		result.okay = false;
		result.err_no = errno;

		return result;
	}

	*count = 0;
	while ((dp = readdir(dir_fd)) != NULL && *count < max_count) {
		cur_attr = (*contents) + *count;
		/* copy the file name */
		cur_attr->file.type = TC_FILE_PATH;

		POSIX_WARN("DirEntry  : %s\n", dp->d_name);

		/* Skip the current and parent directory entry */
		if (!strncmp(dp->d_name, ".", strlen(dp->d_name)) ||
		    !strncmp(dp->d_name, "..", strlen(dp->d_name)))
			continue;

		char *file_path =
		    (char *)calloc(1, strlen(dp->d_name) + strlen(dir) + 2);
		strncpy(file_path, dir, strlen(dir));
		strncat(file_path, "/", 1);
		strncat(file_path, dp->d_name, strlen(dp->d_name));
		cur_attr->file.path = file_path;

		struct stat st;
		file_name[0] = 0;
		strcpy(file_name, dir);
		strcat(file_name, "/");
		strcat(file_name, dp->d_name);

		if (stat(file_name, &st) < 0) {
			result.okay = false;
			result.err_no = errno;
			result.index = *count;

			POSIX_WARN("stat failed for file : %s\n", dp->d_name);

			return result;
		}

		/* copy the attributes */
		tc_get_attrs_from_stat(&st, cur_attr);

		(*count)++;
	}

	return result;
}

tc_res posix_copyv(struct tc_extent_pair *pairs, int count, bool is_transaction)
{
	int i;
	ssize_t ret;
	tc_res tcres = { .okay = true };

	for (i = 0; i < count; ++i) {
		ret = splice_copy(pairs[i].src_path, pairs[i].src_offset,
				  pairs[i].dst_path, pairs[i].dst_offset,
				  pairs[i].length);
		if (ret < 0) {
			tcres.okay = false;
			tcres.index = i;
			tcres.err_no = -ret;
			return tcres;
		}
		pairs[i].length = ret;
	}

	return tcres;
}

int posix_chdir(const char *path)
{
	int ret;

	ret = chdir(path);
	if (ret == -1) {
		ret = -errno;
	}

	return ret;
}

char *posix_getcwd()
{
	return get_current_dir_name();
}
