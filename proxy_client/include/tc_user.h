/* User header file for exported tc features */

#include "export_mgr.h"
#include "ganesha_list.h"

#define USE_SPECIAL_STATE 1
#define USE_NORMAL_STATE 2

/*
 * Contents of an individual read
 * Several of these can be combined to form a list of reads
 */
struct user_read_arg
{
	size_t read_offset;
	size_t read_len;
	char *read_buf;
	struct glist_head read_list;
};

/*
 * Contents of a kernel tcread request
 * dir_fh - Parent directory of the file
 * name - Name of the file that has to be opened
 * read_args - Pointer to the list of reads between open and close
 * open_mode - Whether to use stateid sent by open or special stateid
 */
struct user_tcread_args
{
	struct fsal_obj_handle *dir_fh;
	char *name;
	struct user_read_arg *read_args;
	int open_mode;
};

/*
 * Contents of an individual write
 * Several of these can be combined to form a list of write
 */
struct user_write_arg
{
	size_t write_offset;
	size_t write_len;
	char *write_buf;
	struct glist_head write_list;
};

/*
 * Contents of a kernel tcwrite request
 * dir_fh - Parent directory of the file
 * name - Name of the file that has to be opened
 * write_args - Pointer to the list of writes between open and close
 * open_mode - Whether to use stateid sent by open or special stateid
 */

struct user_tcwrite_args
{
	struct fsal_obj_handle *dir_fh;
	char *name;
	struct user_write_arg *write_args;
	int open_mode;
};

/* Multiple reads for single file */
fsal_status_t tcread_s(struct gsh_export *export, struct user_tcread_args *arg,
		       int read_count);
/* Single read for multiple files */
fsal_status_t tcread_m(struct gsh_export *export, struct user_tcread_args *arg,
		       int file_count);
/* Multiple writes for single file */
fsal_status_t tcwrite_s(struct gsh_export *export,
			struct user_tcwrite_args *arg, int write_count);
/* Single write for multiple files */
fsal_status_t tcwrite_m(struct gsh_export *export,
			struct user_tcwrite_args *arg, int file_count);

