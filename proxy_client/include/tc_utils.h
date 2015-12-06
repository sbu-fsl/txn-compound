/* Header file for implementing tc features */

#include "export_mgr.h"
#include "ganesha_list.h"
#include "tc_user.h"

/*
 * Contents of an individual read
 * Several of these can be combined to form a list of reads
 */
struct read_arg
{
	struct user_read_arg *user_arg;
	union
	{
		READ4resok *v4_rok;
	} read_ok;
	struct glist_head read_list;
};

/*
 * Contents of a kernel tcread request
 * user_arg - Contains dir_fh, name, etc which are passed by the application
 * read_args - Pointer to the list of reads between open and close
 */
struct kernel_tcread_args
{
	struct user_tcread_args *user_arg;
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
	struct user_write_arg *user_arg;
	union
	{
		WRITE4resok *v4_wok;
	} write_ok;
	struct glist_head write_list;
};

/*
 * Contents of a kernel tcwrite request
 * user_arg - Contains dir_fh, name etc which are passed by the application
 * write_args - Pointer to the list of writes between open and close
 */

struct kernel_tcwrite_args
{
	struct user_tcwrite_args *user_arg;
	struct write_arg *write_args;
	OPEN4resok *opok;
	struct attrlist file_attr;
};

#define MAX_READ_COUNT 10
#define MAX_WRITE_COUNT 10

int test1();
int test2();
bool readdir_reply(const char *name, void *dir_state, fsal_cookie_t cookie);
