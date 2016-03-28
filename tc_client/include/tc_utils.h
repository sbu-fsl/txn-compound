/* Header file for implementing tc features */

#include "export_mgr.h"
#include "ganesha_list.h"
#include "tc_api.h"

/*
 * Structure to be passed to ktcread
 * user_arg - Contains file-path, user buffer, read length, offset, etc
 * which are passed by the user
 */
struct tcread_kargs
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
 * Structure to be passed to ktcwrite
 * user_arg - Contains file-path, user buffer, write length, offset, etc
 * which are passed by the user
 */
struct tcwrite_kargs
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
