#include "fsal.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <assert.h>
#include "tc_impl_posix.h"

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

	LogWarn(COMPONENT_FSAL, "posix_readv() called \n");

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
				result.index = i;
				result.err_no = errno;

				LogWarn(COMPONENT_FSAL, "posix_readv() failed at index : %d\n", result.index);

				break;
			}
		}

		i++;
	}

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
	int flags;

        LogWarn(COMPONENT_FSAL, "posix_writev() called \n");

        while (i < write_count) {
                cur_arg = arg+i;

		if(cur_arg->path != NULL) {
			/* open the requested file */
			flags = O_WRONLY;
			if (cur_arg->is_creation) {
				flags |= O_CREAT;
			}
			fd = open(cur_arg->path, flags);
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
				result.err_no = errno;
				result.index = i;

				LogWarn(COMPONENT_FSAL, "posix_writev() failed at index : %d\n", result.index);

				break;
			}
		}

                i++;
        }

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
	if(attr_obj->masks.has_mode)
		attr_obj->mode = st->st_mode;

	if(attr_obj->masks.has_size)
		attr_obj->size = st->st_size;

	if(attr_obj->masks.has_nlink)
		attr_obj->nlink = st->st_nlink;

	if(attr_obj->masks.has_uid)
		attr_obj->uid = st->st_uid;

	if(attr_obj->masks.has_gid)
		attr_obj->gid = st->st_gid;

	if(attr_obj->masks.has_rdev)
		attr_obj->rdev = st->st_rdev;

	if(attr_obj->masks.has_atime)
		attr_obj->atime = st->st_atime;

	if(attr_obj->masks.has_mtime)
		attr_obj->mtime = st->st_mtime;

	if(attr_obj->masks.has_ctime)
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

	LogWarn(COMPONENT_FSAL, "posix_getattrsv() called \n");

	while(i<count) {
		if(cur_attr->path != NULL) {

			/* get attributes */
			if(stat(cur_attr->path, &st)<0) {
				result.okay = false;
				result.err_no = errno;
        			result.index = i;
        			LogWarn(COMPONENT_FSAL, "posix_getattrsv() failed at index : %d\n", result.index);
				break;
			}

			/* copy stat output */
			copy_attrs(&st, cur_attr); 

		}

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
	if(attrs->masks.has_nlink) {
		LogWarn(COMPONENT_FSAL, "set_attrs() failed : nlink attribute bit"
			 		" should not be set \n");
		return -1;
	}

	/* check if rdev bit is set, if set return with error */
	if(attrs->masks.has_rdev) {
                LogWarn(COMPONENT_FSAL, "set_attrs() failed : rdev attribute bit"
                         		" should not be set \n");
		return -1;
	}


	/* set the mode */
	if(attrs->masks.has_mode) {
		res = chmod(attrs->path, attrs->mode);
		if(res < 0) {
			LogWarn(COMPONENT_FSAL, "helper_set_attrs() failed in setting"
				 "attribute 'permissions'  of file %s\n",
					attrs->path);
			goto exit;
		}
	}

	/* set the file size */
	if(attrs->masks.has_size){
		res = truncate(attrs->path, attrs->size);
                if(res < 0) {
			LogWarn(COMPONENT_FSAL, "helper_set_attrs() failed in setting"
				" attribute size of the file %s \n", attrs->path);
                        goto exit;
		}
	}

	/* set the UID and GID */
	if(attrs->masks.has_uid || attrs->masks.has_gid) {
		res = chown(attrs->path, attrs->uid, attrs->gid);

		if(res < 0) {
			LogWarn(COMPONENT_FSAL, "helper_set_attrs() failed in setting "
				 "attributes 'UID and GID' of the file %s\n", attrs->path);
			goto exit;
		}
	}

	/* set the atime and mtime */
	if(attrs->masks.has_atime || attrs->masks.has_mtime) {

        	stat(attrs->path, &s);
        	times[0].tv_sec = s.st_atime;
        	times[1].tv_sec = s.st_mtime;


		if(attrs->masks.has_atime)
			times[0].tv_sec = attrs->atime;

		if(attrs->masks.has_mtime)
			times[1].tv_sec = attrs->mtime;

        	res = utimes(attrs->path, times);

		if(res < 0) {
			LogWarn(COMPONENT_FSAL, "helper_set_attrs() failed in setting the "
				 "attributes 'atime and mtime' of the file %s\n", attrs->path);

			goto exit;
		}

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
	struct tc_attrs *cur_attr = attrs;
	tc_res result = { .okay = true, .index = -1, .err_no = 0 };

	LogWarn(COMPONENT_FSAL, "posix_setattrsv() called \n");

	while(i<count) {
		if(cur_attr->path != NULL) {

			/* Set the attributes if corrseponding mask bit is set */
			if(helper_set_attrs(cur_attr) < 0) {
				result.okay = false;
				result.err_no = errno;
        			result.index = i;
        			LogWarn(COMPONENT_FSAL, "posix_setattrsv() failed at index : %d\n",
										result.index);
				break;
			}
		}

		i++;
	}

	return result;
}
