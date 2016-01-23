#include "fsal.h"
#include <unistd.h>
#include <fcntl.h>
#include <utime.h>
#include <assert.h>
#include "tc_api.h"

/*
 * arg - Array of reads for one or more files
 *       Contains file-path, read length, offset, etc.
 * read_count - Length of the above array
 *              (Or number of reads)
 */
tc_res posix_readv(struct tc_iovec *arg, int read_count, bool is_transaction)
{
	int fd, amount_read, i=0;
	struct tc_iovec *cur_arg = NULL;
	tc_res result = { .okay = true, .index = -1, .err_no = 0 };

	LogDebug(COMPONENT_FSAL, "posix_readv() called \n");

	while (i < read_count) {
		cur_arg = arg+i;

		if(cur_arg->path != NULL) {
			fd = open(cur_arg->path, O_RDONLY);
			if(fd < 0) {
				result.okay = false;
				break;
			}

			/* Read data */	
			amount_read = pread(fd, cur_arg->data, cur_arg->length, cur_arg->offset);
			if(amount_read < 0) {
				close(fd);
				result.okay = false;
				break;
			}

			/* set the length to number of bytes successfully read */
			cur_arg->length = amount_read;

			if(close(fd) < 0) {
				result.okay = false;
				break;
			}
		}

		i++;
	}
	if(result.okay)
		goto exit;
 
	result.index = i;
	result.err_no = errno;
	LogDebug(COMPONENT_FSAL, "posix_readv() failed at index : %d\n", result.index);

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
	int fd, amount_written, i=0;
        struct tc_iovec *cur_arg = NULL;
	tc_res result = { .okay = true, .index = -1, .err_no = 0 };

        LogDebug(COMPONENT_FSAL, "posix_writev() called \n");

        while (i < write_count) {
                cur_arg = arg+i;

		if(cur_arg->path != NULL) {
			/* open the requested file */
                	fd = open(cur_arg->path, O_WRONLY);
                	if(fd < 0) {
				result.okay = false;
                		break;
			}

			/* Write data */
                	amount_written = pwrite(fd, cur_arg->data, cur_arg->length, cur_arg->offset);

                	if(amount_written < 0) {
				close(fd);
				result.okay = false;
                        	break;
			}

			/* set the length to number of bytes successfully written */
			cur_arg->length = amount_written;

                	if(close(fd) < 0) {
				result.okay = false;
				break;
			}
		}

                i++;
        }

	
	if(result.okay)
		goto exit;

	result.err_no = errno;
	result.index = i;
	LogDebug(COMPONENT_FSAL, "posix_writev() failed at index : %d\n", result.index);

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
	if(POSIX_TEST_MASK(attr_obj->masks.has_mode))
		attr_obj->mode = st->st_mode;

	if(POSIX_TEST_MASK(attr_obj->masks.has_size))
		attr_obj->size = st->st_size;

	if(POSIX_TEST_MASK(attr_obj->masks.has_nlink))
		attr_obj->nlink = st->st_nlink;

	if(POSIX_TEST_MASK(attr_obj->masks.has_uid))
		attr_obj->uid = st->st_uid;

	if(POSIX_TEST_MASK(attr_obj->masks.has_gid))
		attr_obj->gid = st->st_gid;

	if(POSIX_TEST_MASK(attr_obj->masks.has_rdev))
		attr_obj->rdev = st->st_rdev;

	if(POSIX_TEST_MASK(attr_obj->masks.has_atime))
		attr_obj->atime = st->st_atime;

	if(POSIX_TEST_MASK(attr_obj->masks.has_mtime))
		attr_obj->mtime = st->st_mtime;

	if(POSIX_TEST_MASK(attr_obj->masks.has_ctime))
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
	int fd = -1, i = 0;
	struct tc_attrs *cur_attr = attrs;
	tc_res result = { .okay = true, .index = -1, .err_no = 0 };
	struct stat st;

	LogDebug(COMPONENT_FSAL, "posix_getattrsv() called \n");

	while(i<count) {
		if(cur_attr->path != NULL) {

			/*
			 * TODO: make the process efficient by avoiding
			 * unnecessary open/close if adjacent entries
			 * are for the same file
			 */
			fd = open(cur_attr->path, O_RDONLY);
			
			if(fd < 0) {
				result.okay = false;
				break;
			}

			/* get attributes */
			if(fstat(fd, &st)<0) {
				close(fd);
				result.okay = false;
				break;
			}

			/* copy stat output */
			copy_attrs(&st, cur_attr); 

			if(close(fd) < 0) {
				result.okay = false;
				break;
			}
		}

		i++;
	}

	if(result.okay)
		goto exit;

	result.err_no = errno;
        result.index = i;
        LogDebug(COMPONENT_FSAL, "posix_getattrsv() failed at index : %d\n", result.index);

exit:
	return result;
}


int helper_set_attrs(const char *path, struct tc_attrs *attrs)
{
	int res = 0;
	struct utimbuf time_buf;

	/* set the mode */
	if(POSIX_TEST_MASK(attrs->masks.has_mode)) {
		res = chmod(path, attrs->mode);
		if(res < 0)
			goto exit;
	}

	/* set the file size */
	if(POSIX_TEST_MASK(attrs->masks.has_size)){
		res = truncate(path, attrs->size);
                if(res < 0)
                        goto exit;
	}

	/* set the UID and GID */
	if(POSIX_TEST_MASK(attrs->masks.has_uid) ||
	   POSIX_TEST_MASK(attrs->masks.has_gid)) {
		res = chown(path, attrs->uid, attrs->gid);

		if(res < 0)
			goto exit;
	}

	/* set the atime and mtime */
	if(POSIX_TEST_MASK(attrs->masks.has_atime) ||
	   POSIX_TEST_MASK(attrs->masks.has_mtime)) {

		if(POSIX_TEST_MASK(attrs->masks.has_atime))
			time_buf.actime = attrs->atime;

		if(POSIX_TEST_MASK(attrs->masks.has_mtime))
			time_buf.modtime = attrs->mtime;

		res = utime(path, &time_buf);

		if(res < 0)
			goto exit;

	}

	/* check if nlink bit is set, if set return with error */
	if(POSIX_TEST_MASK(attrs->masks.has_nlink)) {
		LogDebug(COMPONENT_FSAL, "set_attrs() failed : nlink bit"
			 " should not be set \n");
		res = -1;
	}

	/* check if rdev bit is set, if set return with error */
	if(POSIX_TEST_MASK(attrs->masks.has_rdev)) {
                LogDebug(COMPONENT_FSAL, "set_attrs() failed : rdev bit"
                         " should not be set \n");
		res = -1;
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
tc_res tc_setattrsv(struct tc_attrs *attrs, int count, bool is_transaction)
{
	int fd = -1, i = 0;
	struct tc_attrs *cur_attr = attrs;
	tc_res result = { .okay = true, .index = -1, .err_no = 0 };

	LogDebug(COMPONENT_FSAL, "posix_setattrsv() called \n");

	while(i<count) {
		if(cur_attr->path != NULL) {

			/* Set the attributes if corrseponding mask bit is set */
			if(helper_set_attrs(cur_attr->path, cur_attr) < 0) {
				result.okay = false;
				break;
			}
		}

		i++;
	}

	if(result.okay)
		goto exit;

	result.err_no = errno;
        result.index = i;
        LogDebug(COMPONENT_FSAL, "posix_setattrsv() failed at index : %d\n", result.index);

exit:
	return result;
}
