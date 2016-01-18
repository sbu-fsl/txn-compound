#include "config"

#include "fsal.h"
#include <unistd.h>
#include <fcntl.h>
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

