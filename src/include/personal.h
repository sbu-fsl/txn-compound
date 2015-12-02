#include "export_mgr.h"
#include "ganesha_list.h"

struct pxy_read_args {
	size_t read_offset;
        size_t read_len;
        char *read_buf;
	READ4resok *rok;
	struct glist_head read_list;
};

struct pxy_tcread_args {
	struct fsal_obj_handle *dir_fh;
	char *name;
	struct pxy_read_args *read_args;
	OPEN4resok *opok;
	struct attrlist file_attr;
};

struct pxy_write_args {
	size_t write_offset;
	size_t write_len;
	char *write_buf;
	WRITE4resok *wok;
	struct glist_head write_list;
};

struct pxy_tcwrite_args {
	struct fsal_obj_handle *dir_fh;
	char *name;
	struct pxy_write_args *write_args;
	OPEN4resok *opok;
	struct attrlist file_attr;
};

int personal_init();
int personal1_init();
bool
readdir_reply(const char *name, void *dir_state,
                fsal_cookie_t cookie);
