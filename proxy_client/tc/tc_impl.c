#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <assert.h>
#include "tc_api.h"
#include "posix/tc_impl_posix.h"

static tc_res TC_OKAY = { .okay = true, .index = -1, .err_no = 0, };

tc_res tc_readv(struct tc_iovec *reads, int count, bool is_transaction)
{
	/**
	 * TODO: check if the functions should use posix or TC depending on the
	 * back-end file system.
	 */
	return posix_readv(reads, count, is_transaction);
}

tc_res tc_writev(struct tc_iovec *writes, int count, bool is_transaction)
{
	return posix_writev(writes, count, is_transaction);
}

tc_res tc_getattrsv(struct tc_attrs *attrs, int count, bool is_transaction)
{
	return posix_getattrsv(attrs, count, is_transaction);
}

tc_res tc_setattrsv(struct tc_attrs *attrs, int count, bool is_transaction)
{
	return posix_setattrsv(attrs, count, is_transaction);
}

void tc_free_attrs(struct tc_attrs *attrs, int count, bool free_path)
{
	int i;

	if (free_path) {
		for (i = 0; i < count; ++i) {
			if (attrs[i].file.type == FILE_PATH)
				free((char *)attrs[i].file.path);
		}
	}
	free(attrs);
}

tc_res tc_listdir(const char *dir, struct tc_attrs_masks masks, int max_count,
		  struct tc_attrs **contents, int *count)
{
	return posix_listdir(dir, masks, max_count, contents, count);
}

tc_res tc_renamev(tc_file_pair *pairs, int count, bool is_transaction)
{
	return posix_renamev(pairs, count, is_transaction);
}

tc_res tc_removev(tc_file *files, int count, bool is_transaction)
{
	return posix_removev(files, count, is_transaction);
}

tc_res tc_mkdirv(tc_file *dir, mode_t *mode, int count, bool is_transaction)
{
	return posix_mkdirv(dir, mode, count, is_transaction);
}

tc_res tc_copyv(struct tc_extent_pair *pairs, int count, bool is_transaction)
{
	return TC_OKAY;
}

tc_res tc_write_adb(struct tc_adb *patterns, int count, bool is_transaction)
{
	return TC_OKAY;
}
