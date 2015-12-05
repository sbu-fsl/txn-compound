#include "export_mgr.h"
#include "ganesha_list.h"

/*
 * Contents of an individual read
 * Several of these can be combined to form a list of reads
 */
struct read_arg
{
	size_t read_offset;
	size_t read_len;
        char *read_buf;
	READ4resok *rok;
	struct glist_head read_list;
};

/*
 * Contents of a kernel tcread request
 * dir_fh - Parent directory of the file
 * name - Name of the file that has to be opened
 * read_args - Pointer to the list of reads between open and close
 */
struct kernel_tcread_args
{
	struct fsal_obj_handle *dir_fh;
	char *name;
	struct read_arg *read_args;
	OPEN4resok *opok;
	struct attrlist file_attr;
};

/*
 * Contents of an individual write
 * Several of these can be combined to form a list of write
 */
struct write_arg
{
	size_t write_offset;
	size_t write_len;
	char *write_buf;
	WRITE4resok *wok;
	struct glist_head write_list;
};

/*
 * Contents of a kernel tcwrite request
 * dir_fh - Parent directory of the file
 * name - Name of the file that has to be opened
 * write_args - Pointer to the list of reads between open and close
 */

struct kernel_tcwrite_args
{
	struct fsal_obj_handle *dir_fh;
	char *name;
	struct write_args *write_args;
	OPEN4resok *opok;
	struct attrlist file_attr;
};

int test1();
int test2();
bool readdir_reply(const char *name, void *dir_state, fsal_cookie_t cookie);
