#include "config.h"
#include <ctype.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "fsal_types.h"
#include "fsal.h"
#include "FSAL/fsal_init.h"
#include "pxy_fsal_methods.h"
#include "fsal_api.h"
#include "personal.h"

bool
readdir_reply(const char *name, void *dir_state,
                fsal_cookie_t cookie)
{
	LogDebug(COMPONENT_FSAL, "readdir_reply() called\n");
	return true;
}

int personal_init()
{
	struct pxy_fsal_module *new_module = NULL;
	struct pxy_tcread_args tcread_arg[2];
	struct pxy_read_args *temp_head = NULL;
	struct pxy_read_args *temp_arg = NULL;
	char *name = NULL;
	char *name1 = NULL;
	struct gsh_export *export = NULL;
	struct fsal_obj_handle *root_handle = NULL;
	struct fsal_obj_handle *vfs0_handle = NULL;
	struct fsal_obj_handle *abcd_handle = NULL;
	struct fsal_obj_handle *abcd1_handle = NULL;
	fsal_status_t fsal_status = { 0, 0 };
	char *data_buf = NULL;
	char *data_buf1 = NULL;
	size_t read_amount = 0;
	bool eof = false;
	struct glist_head *temp_read, *temp_read1;
	struct attrlist abcd_attr;
	struct attrlist abcd1_attr;
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

	
	sleep(1);

	memset(&req_ctx, 0, sizeof(struct req_op_context));
	op_ctx = &req_ctx;
	op_ctx->creds = NULL;
	op_ctx->fsal_export = export->fsal_export;

	fsal_status = export->fsal_export->obj_ops->root_lookup(NULL, "vfs0", &root_handle);
        //fsal_status = export->fsal_export->obj_ops->lookup(NULL, "home", &vfs0_handle);
	if (FSAL_IS_ERROR(fsal_status)) {
		LogDebug(COMPONENT_FSAL, "lookup() for root failed\n");
	}

	LogDebug(COMPONENT_FSAL, "lookup() for root succeeded\n");

	if (root_handle == NULL) {
                LogDebug(COMPONENT_FSAL, "root_handle is NULL\n");
                return -1;
        }

	//fsal_status = pxy_lookup(NULL, "vfs0", &vfs0_handle);
	fsal_status = export->fsal_export->obj_ops->lookup(root_handle, "vfs0", &vfs0_handle);
	//fsal_status = export->fsal_export->obj_ops->lookup(NULL, "home", &vfs0_handle);
	if (FSAL_IS_ERROR(fsal_status)) {
		LogDebug(COMPONENT_FSAL, "lookup() for vfs0 failed\n");
		return -1;
	}

	LogDebug(COMPONENT_FSAL, "lookup() for vfs0 succeeded\n");
	if (vfs0_handle == NULL) {
		LogDebug(COMPONENT_FSAL, "vfs0_handle is NULL\n");
		return -1;
	}

	fsal_status = export->fsal_export->obj_ops->lookup(vfs0_handle, "abcd", &abcd_handle);
	if (FSAL_IS_ERROR(fsal_status)) {
                LogDebug(COMPONENT_FSAL, "lookup() for abcd failed\n");
		return -1;
        }

	LogDebug(COMPONENT_FSAL, "lookup() for abcd succeeded\n");
	if (abcd_handle == NULL) {
		LogDebug(COMPONENT_FSAL, "abcd_handle is NULL\n");
		return -1;
	}

	fsal_status = export->fsal_export->obj_ops->read(abcd_handle, 0, 1024, data_buf, &read_amount, &eof);
	if (FSAL_IS_ERROR(fsal_status)) {
                LogDebug(COMPONENT_FSAL, "read() for abcd failed\n");
                return -1;
        }

	LogDebug(COMPONENT_FSAL, "read() for abcd succeeded\n");
	LogDebug(COMPONENT_FSAL, "amount read: %u\n", read_amount);

	fsal_status = export->fsal_export->obj_ops->getattrs(abcd_handle);
	if (FSAL_IS_ERROR(fsal_status)) {
                LogDebug(COMPONENT_FSAL, "getattr() for abcd failed\n");
                return -1;
        }

	LogDebug(COMPONENT_FSAL, "getattr() for abcd succeeded\n");

	fsal_status = export->fsal_export->obj_ops->readdir(abcd_handle, NULL, NULL, readdir_reply, &eof);
	if (FSAL_IS_ERROR(fsal_status)) {
                LogDebug(COMPONENT_FSAL, "read_dir() for abcd failed\n");
        }

	fsal_status = export->fsal_export->obj_ops->readdir(vfs0_handle, NULL, NULL, readdir_reply, &eof);
        if (FSAL_IS_ERROR(fsal_status)) {
                LogDebug(COMPONENT_FSAL, "read_dir() for vfs0 failed\n");
                return -1;
        }

        LogDebug(COMPONENT_FSAL, "readdir() for vfs0 succeeded\n");

	read_amount = 0;
	fsal_status = export->fsal_export->obj_ops->write(abcd_handle, 0, 12, "check write", &read_amount, &eof);
        if (FSAL_IS_ERROR(fsal_status)) {
                LogDebug(COMPONENT_FSAL, "write() for abcd failed\n");
                return -1;
        }

	LogDebug(COMPONENT_FSAL, "write() for abcd succeeded, %u written\n", read_amount);

	abcd_handle = NULL;
/*
	fsal_status = export->fsal_export->obj_ops->openread(vfs0_handle, "abcd", "abcd1",
								&abcd_attr, &abcd1_attr,
								&abcd_handle, &abcd1_handle);
	if (FSAL_IS_ERROR(fsal_status)) {
                LogDebug(COMPONENT_FSAL, "openread() for abcd failed\n");
                return -1;
        }


	LogDebug(COMPONENT_FSAL, "openread() for abcd succeeded\n");
*/

	tcread_arg[0].dir_fh = vfs0_handle;
	name = malloc(strlen("abcd")+1);
	strncpy(name,"abcd",strlen("abcd")+1);
	tcread_arg[0].name = name;
	temp_head = malloc(sizeof(struct pxy_read_args));
	temp_head->read_offset = 0;
	temp_head->read_len = 256;
	data_buf = malloc(256);
	temp_head->read_buf = data_buf;
	tcread_arg[0].read_args = temp_head;
	glist_init(&(tcread_arg[0].read_args->read_list));

	temp_arg = malloc(sizeof(struct pxy_read_args));
	temp_arg->read_offset = 256;
        temp_arg->read_len = 256;
        temp_arg->read_buf = data_buf1;
	glist_add_tail(&(tcread_arg[0].read_args->read_list), &(temp_arg->read_list));

	temp_arg = malloc(sizeof(struct pxy_read_args));
        temp_arg->read_offset = 512;
        temp_arg->read_len = 256;
        temp_arg->read_buf = data_buf1;
        glist_add_tail(&(tcread_arg[0].read_args->read_list), &(temp_arg->read_list));

	//tcread_arg[0].read_offset = 0;
	//tcread_arg[0].read_len = 1024;
	

	tcread_arg[1].dir_fh = vfs0_handle;
	name1 = malloc(strlen("abcd1")+1);
	strncpy(name1,"abcd1",strlen("abcd1")+1);
	tcread_arg[1].name = name1;
	temp_head = malloc(sizeof(struct pxy_read_args));
	temp_head->read_offset = 0;
	temp_head->read_len = 512;
	temp_head->read_buf = data_buf1;
	tcread_arg[1].read_args = temp_head;
	glist_init(&(tcread_arg[1].read_args->read_list));

	temp_arg = malloc(sizeof(struct pxy_read_args));
	temp_arg->read_offset = 512;
	temp_arg->read_len = 512;
	temp_arg->read_buf = data_buf1;
	glist_add_tail(&(tcread_arg[1].read_args->read_list), &(temp_arg->read_list));

	temp_arg = malloc(sizeof(struct pxy_read_args));
        temp_arg->read_offset = 1024;
        temp_arg->read_len = 512;
        temp_arg->read_buf = data_buf1;
        glist_add_tail(&(tcread_arg[1].read_args->read_list), &(temp_arg->read_list));

	//tcread_arg[1].read_offset = 10;
	//tcread_arg[1].read_len = 1024;

	fsal_status = export->fsal_export->obj_ops->tc_read(tcread_arg, 2, 3);

	free(tcread_arg[0].name);
	free(tcread_arg[1].name);
	glist_for_each_safe(temp_read, temp_read1, &(tcread_arg[0].read_args->read_list)) {
		struct pxy_read_args *read_arg_temp =
			container_of(temp_read, struct pxy_read_args, read_list);
		LogDebug(COMPONENT_FSAL, "freed0\n");
		glist_del(temp_read);
		free(read_arg_temp);
	}

	LogDebug(COMPONENT_FSAL, "Buf: %s \n", tcread_arg[0].read_args->read_buf);

	free(tcread_arg[0].read_args->read_buf);
	free(tcread_arg[0].read_args);

	glist_for_each_safe(temp_read, temp_read1, &(tcread_arg[1].read_args->read_list)) {
		struct pxy_read_args *read_arg_temp =
			container_of(temp_read, struct pxy_read_args, read_list);
		LogDebug(COMPONENT_FSAL, "freed1\n");
		glist_del(temp_read);
		free(read_arg_temp);
	}

	free(tcread_arg[1].read_args);

	if (FSAL_IS_ERROR(fsal_status)) {
		LogDebug(COMPONENT_FSAL, "tc_read() for abcd failed\n");
		return -1;
	}

	LogDebug(COMPONENT_FSAL, "tc_read() for abcd succeeded\n");

	return 0;
}
