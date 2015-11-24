#include "export_mgr.h"
#include "ganesha_list.h"

struct pxy_read_args {
	size_t read_offset;
        size_t read_len;
        char *read_buf;
	struct glist_head read_list;
};

struct pxy_tcread_args {
	struct fsal_obj_handle *dir_fh;
	char *name;
	struct pxy_read_args *read_args;
	struct fsal_obj_handle *file_handle;
	struct attrlist file_attr;
};
int personal_init();
bool
readdir_reply(const char *name, void *dir_state,
                fsal_cookie_t cookie);
