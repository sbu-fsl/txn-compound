/* Header file for implementing tc features */

#include "export_mgr.h"
#include "ganesha_list.h"
#include "tc_user.h"

/*
 * Contents of a kernel tcread request
 * user_arg - Contains dir_fh, name, etc which are passed by the application
 * read_args - Pointer to the list of reads between open and close
 */
struct kernel_tcread_args
{
	struct tc_iovec *user_arg;
	char *path;
	union
	{
		READ4resok *v4_rok;
	} read_ok;
	OPEN4resok *opok_handle;
	struct attrlist attrib;
};

/*
 * Contents of a kernel tcwrite request
 * user_arg - Contains dir_fh, name etc which are passed by the application
 * write_args - Pointer to the list of writes between open and close
 */

struct kernel_tcwrite_args
{
	struct tc_iovec *user_arg;
	char *path;
	union
	{
		WRITE4resok *v4_wok;
	} write_ok;
	OPEN4resok *opok_handle;
	struct attrlist attrib;
};

#define MAX_READ_COUNT      10
#define MAX_WRITE_COUNT     10
#define MAX_DIR_DEPTH       10
#define MAX_FILENAME_LENGTH 256

int test1();
int test2();
bool readdir_reply(const char *name, void *dir_state, fsal_cookie_t cookie);
