#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <assert.h>
#include "tc_api.h"

static tc_res TC_OKAY = {
	.okay = true,
	.index = -1,
	.errno = 0,
};

tc_res tc_readv(struct tc_iovec *reads, int count, bool is_transaction) {
	return TC_OKAY;
}

tc_res tc_writev(struct tc_iovec *writes, int count, bool is_transaction) {
	return TC_OKAY;
}

tc_res tc_getattrsv(struct tc_attrs *attrs, int count, bool is_transaction) {
	return TC_OKAY;
}

tc_res tc_setattrsv(struct tc_attrs *attrs, int count, bool is_transaction) {
	return TC_OKAY;
}

void tc_free_attrs(struct tc_attrs *attrs, int count, bool free_path) {
	int i;

	if (free_path) {
		for (i = 0; i < count; ++i) {
			free((char *)attrs[i].path);
		}
	}
	free(attrs);
}

tc_res tc_listdir(const char *dir, struct tc_attrs_masks masks, int max_count,
		  struct tc_attrs **contents, int *count) {
	return TC_OKAY;
}

tc_res tc_renamev(struct tc_file_pair *pairs, int count, bool is_transaction) {
	return TC_OKAY;
}

tc_res tc_copyv(struct tc_extent_pair *pairs, int count, bool is_transaction) {
	return TC_OKAY;
}

tc_res tc_write_adb(struct tc_adb *patterns, int count, bool is_transaction) {
	return TC_OKAY;
}
