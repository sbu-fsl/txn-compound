#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <assert.h>
#include <stdio.h>

#include "tc_impl_posix.h"

#define POSIX_WARN(fmt, args...) fprintf(stderr, "==posix-WARN==" fmt, ##args)

/*
 * open routine for POSIX files
 * path - file path
 * flags - open flags
 */

tc_file posix_open(const char *path, int flags)
{
	tc_file file;
	int fd = open(path, flags);

	file.type = FILE_DESCRIPTOR;
	file.fd = fd;

	return file;
}

/*
 * close routine for POSIX files
 * file - tc_file structure with file
 * descriptor value.
 */

int posix_close(const tc_file *file)
{
	int err = 0;

	assert(file->type == FILE_DESCRIPTOR);

	/* return error no in case of failure */
	if (close(file->fd) < 0)
		err = errno;

	return err;
}

/*
 * arg - Array of reads for one or more files
 *       Contains file-path, read length, offset, etc.
 * read_count - Length of the above array
 *              (Or number of reads)
 */
tc_res posix_readv(struct tc_iovec *arg, int read_count, bool is_transaction)
{
	int fd, amount_read, i = 0;
	tc_file file = { 0 };
	struct tc_iovec *cur_arg = NULL;
	tc_res result = { .okay = true, .index = -1, .err_no = 0 };

	POSIX_WARN("posix_readv() called \n");

	while (i < read_count) {
		cur_arg = arg + i;

		/*
		 * if the user specified the path and not file descriptor
		 * then call open to obtain the file descriptor else
		 * go ahead with the file descriptor specified by the user
		 */
		if (cur_arg->file.type == FILE_PATH)
			file = posix_open(cur_arg->file.path, O_RDONLY);
		else
			file = cur_arg->file;

		fd = file.fd;
		if (fd < 0) {
			result.okay = false;
			break;
		}

		/* Read data */
		amount_read =
		    pread(fd, cur_arg->data, cur_arg->length, cur_arg->offset);
		if (amount_read < 0) {
			if (cur_arg->file.type == FILE_PATH)
				posix_close(&file);
			result.okay = false;
			break;
		}

		/* set the length to number of bytes successfully read */
		cur_arg->length = amount_read;

		if (cur_arg->file.type == FILE_PATH && posix_close(&file) < 0) {
			result.okay = false;
			break;
		}

		i++;
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
	int fd, amount_written, i = 0;
	tc_file file = { 0 };
	struct tc_iovec *cur_arg = NULL;
	tc_res result = { .okay = true, .index = -1, .err_no = 0 };
	int flags;

	POSIX_WARN("posix_writev() called \n");

	while (i < write_count) {
		cur_arg = arg + i;

		/* open the requested file */
		flags = O_WRONLY;
		if (cur_arg->is_creation) {
			flags |= O_CREAT;
		}

		if (cur_arg->file.type == FILE_PATH)
			file = posix_open(cur_arg->file.path, flags);
		else
			file = cur_arg->file;

		fd = file.fd;
		if (fd < 0) {
			result.okay = false;
			break;
		}

		/* Write data */
		amount_written =
		    pwrite(fd, cur_arg->data, cur_arg->length, cur_arg->offset);

		if (amount_written < 0) {
			if (cur_arg->file.type == FILE_PATH)
				posix_close(&file);
			result.okay = false;
			break;
		}

		/* set the length to number of bytes successfully written */
		cur_arg->length = amount_written;

		if (cur_arg->file.type == FILE_PATH && posix_close(&file) < 0) {
			result.okay = false;
			break;
		}

		i++;
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

	if (attr_obj->masks.has_atime)
		attr_obj->atime = st->st_atime;

	if (attr_obj->masks.has_mtime)
		attr_obj->mtime = st->st_mtime;

	if (attr_obj->masks.has_ctime)
		attr_obj->ctime = st->st_ctime;
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
		if (cur_attr->file.type == FILE_PATH)
			res = stat(cur_attr->file.path, &st);
		else
			res = fstat(cur_attr->file.fd, &st);

		if (res < 0) {
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
		if (attrs->file.type == FILE_PATH)
			res = chmod(attrs->file.path, attrs->mode);
		else
			res = fchmod(attrs->file.fd, attrs->mode);

		if (res < 0)
			goto exit;
	}

	/* set the file size */
	if (attrs->masks.has_size) {
		if (attrs->file.type == FILE_PATH)
			res = truncate(attrs->file.path, attrs->size);
		else
			res = ftruncate(attrs->file.fd, attrs->size);

		if (res < 0)
			goto exit;
	}

	/* set the UID and GID */
	if (attrs->masks.has_uid || attrs->masks.has_gid) {

		if (attrs->file.type == FILE_PATH)
			res = chown(attrs->file.path, attrs->uid, attrs->gid);
		else
			res = fchown(attrs->file.fd, attrs->uid, attrs->gid);

		if (res < 0)
			goto exit;
	}

	/* set the atime and mtime */
	if (attrs->masks.has_atime || attrs->masks.has_mtime) {

		if (attrs->file.type == FILE_PATH)
			stat(attrs->file.path, &s);
		else
			fstat(attrs->file.fd, &s);

		times[0].tv_sec = s.st_atime;
		times[1].tv_sec = s.st_mtime;

		if (attrs->masks.has_atime)
			times[0].tv_sec = attrs->atime;

		if (attrs->masks.has_mtime)
			times[1].tv_sec = attrs->mtime;

		if (attrs->file.type == FILE_PATH)
			res = utimes(attrs->file.path, times);
		else
			res = futimens(attrs->file.fd, times);

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
