#include "config.h"
#include <ctype.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "fsal_types.h"
#include "fsal_api.h"
#include "fsal.h"
#include "FSAL/fsal_init.h"
#include "fs_fsal_methods.h"
#include "tc_utils.h"

int test2()
{
	struct fsal_module *new_module = NULL;
	char *name = NULL;
	char *name1 = NULL;
	struct gsh_export *export = NULL;
	struct fsal_obj_handle *cur_handle = NULL;
	struct fsal_obj_handle *root_handle = NULL;
	struct fsal_obj_handle *vfs0_handle = NULL;
	fsal_status_t fsal_status = { 0, 0 };
	char *data_buf = NULL;
	char *data_buf1 = NULL;
	size_t read_amount = 0;
	bool eof = false;
	struct glist_head *temp_read, *temp_read1;
	struct glist_head *temp_write, *temp_write1;
	struct attrlist abcd_attr;
	struct attrlist abcd1_attr;
	struct req_op_context req_ctx;
	int i = 0;

	LogDebug(COMPONENT_FSAL, "test2() called\n");
	new_module = lookup_fsal("PROXY");
	if (new_module == NULL) {
		LogDebug(COMPONENT_FSAL, "Proxy Module Not found\n");
		return -1;
	}
	LogDebug(COMPONENT_FSAL, "Proxy Module Found\n");
	export = get_gsh_export(77);
	if(export == NULL){
		LogDebug(COMPONENT_FSAL, "Export Not found\n");
		return -1;
	}
	LogDebug(COMPONENT_FSAL, "Export Found\n");
	LogDebug(COMPONENT_FSAL,
                 "Export %d at pseudo (%s) with path (%s) and tag (%s) \n",
                 export->export_id, export->pseudopath,
                 export->fullpath, export->FS_tag);

	
	sleep(1);

	memset(&req_ctx, 0, sizeof(struct req_op_context));
	op_ctx = &req_ctx;
	op_ctx->creds = NULL;
	op_ctx->fsal_export = export->fsal_export;

	fsal_status = export->fsal_export->obj_ops->root_lookup(&root_handle);
	if (FSAL_IS_ERROR(fsal_status)) {
		LogDebug(COMPONENT_FSAL, "lookup() for root failed\n");
	}

	LogDebug(COMPONENT_FSAL, "lookup() for root succeeded\n");

	if (root_handle == NULL) {
                LogDebug(COMPONENT_FSAL, "root_handle is NULL\n");
                return -1;
        }

	fsal_status = export->fsal_export->obj_ops->lookup(root_handle, "vfs0", &cur_handle);
	if (FSAL_IS_ERROR(fsal_status)) {
		LogDebug(COMPONENT_FSAL, "lookup() for vfs0 failed\n");
		return -1;
	}

	LogDebug(COMPONENT_FSAL, "lookup() for vfs0 succeeded\n");
	if (cur_handle == NULL) {
		LogDebug(COMPONENT_FSAL, "curr_handle is NULL\n");
		return -1;
	}

	root_handle = cur_handle;
	cur_handle = NULL;

	fsal_status = export->fsal_export->obj_ops->lookup(root_handle, "test", &cur_handle);
	if (FSAL_IS_ERROR(fsal_status)) {
		LogDebug(COMPONENT_FSAL, "lookup() for test failed\n");
		return -1;
	}

	LogDebug(COMPONENT_FSAL, "lookup() for test succeeded\n");
	if (cur_handle == NULL) {
		LogDebug(COMPONENT_FSAL, "curr_handle is NULL\n");
		return -1;
	}

	i = 1;

	return 0;
}
