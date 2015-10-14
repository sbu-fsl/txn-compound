#include "config.h"
#include <ctype.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "fsal_types.h"
#include "fsal.h"
#include "fsal_api.h"
#include "FSAL/fsal_init.h"
#include "pxy_fsal_methods.h"
#include "personal.h"

int personal_init() {
	struct pxy_fsal_module *new_module = NULL;
	struct gsh_export *export = NULL;
	struct fsal_obj_handle *vfs0_handle = NULL;
	fsal_status_t fsal_status = { 0, 0 };
	cache_entry_t *entry = NULL;
	struct req_op_context req_ctx;

	LogDebug(COMPONENT_FSAL, "personal_init() called\n");
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
	
	if(nfs_export_get_root_entry(export, &entry)
                    != CACHE_INODE_SUCCESS){
		LogDebug(COMPONENT_FSAL, "get root() failed\n");
	}
	LogDebug(COMPONENT_FSAL, "get root() success\n");

	memset(&req_ctx, 0, sizeof(struct req_op_context));
	op_ctx = &req_ctx;
	op_ctx->creds = NULL;
	op_ctx->fsal_export = export->fsal_export;

	//fsal_status = pxy_lookup(NULL, "vfs0", &vfs0_handle);
	fsal_status = export->fsal_export->obj_ops->lookup(NULL, "vfs1", &vfs0_handle);
	if (FSAL_IS_ERROR(fsal_status)) {
		LogDebug(COMPONENT_FSAL, "lookup() for vfs0 failed\n");
	}

	LogDebug(COMPONENT_FSAL, "lookup() for vfs0 succeeded\n");

	return 0;
}
