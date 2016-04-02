#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <assert.h>
#include <stdio.h>
#include <dirent.h>
#include <string.h>

#include "tc_impl_posix.h"
#include "log.h"

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

tc_file posix_open(const char *path, int flags)
{
	tc_file file;
	int fd = open(path, flags);

	file.type = TC_FILE_DESCRIPTOR;
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

	assert(file->type == TC_FILE_DESCRIPTOR);

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
		if (cur_arg->file.type == TC_FILE_PATH)
			file = posix_open(cur_arg->file.path, O_RDONLY);
		else
			file = cur_arg->file;

		fd = file.fd;
		if (fd < 0) {
			result.okay = false;
			POSIX_ERR("failed in readv: %s\n", strerror(errno));
			break;
		}

		/* Read data */
		if (cur_arg->offset == -2) {
			off_t offset = lseek(fd, 0, SEEK_CUR);
			POSIX_WARN("Posix read from offset : %d\n", offset);

			amount_read = read(fd, cur_arg->data, cur_arg->length);
		} else
			amount_read = pread(fd, cur_arg->data, cur_arg->length,
					    cur_arg->offset);
		if (amount_read < 0) {
			if (cur_arg->file.type == TC_FILE_PATH)
				posix_close(&file);
			result.okay = false;
			break;
		}

		/* set the length to number of bytes successfully read */
		cur_arg->length = amount_read;

		if (cur_arg->file.type == TC_FILE_PATH &&
		    posix_close(&file) < 0) {
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

		if (cur_arg->file.type == TC_FILE_PATH)
			file = posix_open(cur_arg->file.path, flags);
		else
			file = cur_arg->file;

		fd = file.fd;
		if (fd < 0) {
			result.okay = false;
			break;
		}

		off_t offset = cur_arg->offset;

		/* append */
		if (offset == -1) {
			offset = lseek(fd, 0, SEEK_END);

			if (offset == (off_t) - 1) {
				result.okay = false;
				break;
			}
		}

		/* Write data */
		if (offset == -2) {
			offset = lseek(fd, 0, SEEK_CUR);

			POSIX_WARN("Posix write at offset : %d\n", offset);

			amount_written =
			    write(fd, cur_arg->data, cur_arg->length);
		} else
			amount_written =
			    pwrite(fd, cur_arg->data, cur_arg->length, offset);

		if (amount_written < 0) {
			if (cur_arg->file.type == TC_FILE_PATH)
				posix_close(&file);
			result.okay = false;
			break;
		}

		/* set the length to number of bytes successfully written */
		cur_arg->length = amount_written;

		if (cur_arg->file.type == TC_FILE_PATH &&
		    posix_close(&file) < 0) {
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
			times[0].tv_sec = attrs->atime;

		if (attrs->masks.has_mtime)
			times[1].tv_sec = attrs->mtime;

		if (attrs->file.type == TC_FILE_PATH)
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

		if (unlink(cur_file->path) < 0) {
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

tc_res posix_mkdirv(tc_file *dir, mode_t *mode, int count, bool is_transaction)
{
	int i = 0;
	tc_file *cur_dir = NULL;
	tc_res result = { .okay = true, .index = -1, .err_no = 0 };

	while (i < count) {
		cur_dir = dir + i;

		assert(cur_dir->path != NULL);

		if (mkdir(cur_dir->path, mode[i]) < 0) {
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

	assert(dir != NULL);

	dir_fd = opendir(dir);

	if (dir_fd < 0) {
		result.okay = false;
		result.err_no = errno;

		return result;
	}

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

		/* copy the masks */
		cur_attr->masks = masks;

		struct stat st;
		char *file_name =
		    (char *)calloc(1, sizeof(dir) + sizeof(dp->d_name));
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
		if (masks.has_mode)
			cur_attr->mode = st.st_mode;

		if (masks.has_size)
			cur_attr->size = st.st_size;

		if (masks.has_nlink)
			cur_attr->nlink = st.st_nlink;

		if (masks.has_uid)
			cur_attr->uid = st.st_uid;

		if (masks.has_gid)
			cur_attr->gid = st.st_gid;

		if (masks.has_rdev)
			cur_attr->rdev = st.st_rdev;

		if (masks.has_atime)
			cur_attr->atime = st.st_atime;

		if (masks.has_mtime)
			cur_attr->mtime = st.st_mtime;

		if (masks.has_ctime)
			cur_attr->ctime = st.st_ctime;

		(*count)++;
	}

	return result;
}
