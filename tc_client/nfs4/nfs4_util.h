/* Header file for implementing tc features */

#ifndef __TC_NFS4_UTIL_H__
#define __TC_NFS4_UTIL_H__

#include "export_mgr.h"
#include "tc_impl_nfs4.h"

#ifdef __cplusplus
extern "C" {
#endif

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
#define MAX_FD              1024

struct kfd
{
	int fd; /* fd might not be needed because we will be indexing using
		   array index, so this will be used only to check if an fd is
		   being used. So has to be set to -1 if freed  */
	nfs_fh4 fh;
	char *path;
	/* Export id not needed now, might be needed in future */
	stateid4 stateid;
};

struct kfd fd_list[MAX_FD];
int free_fdlist[MAX_FD];
int freelist_count, freelist_head, freelist_tail;

static inline int init_fd()
{
	int i = 0;
	while (i < MAX_FD) {
		free_fdlist[i] = i;
		fd_list[i].fd = -1;
		fd_list[i].path = NULL;
		i++;
	}

	freelist_count = MAX_FD;
	freelist_head = 0;
	freelist_tail = MAX_FD;
}

static inline int getfdnum()
{
	if (freelist_count <= 0) {
		/* Add error log indicating fd exhaustion */
		return -1;
	}
	return free_fdlist[freelist_head++];
}

/* Helper function to get free count, to be called before sending open to server
 */
static inline int get_freecount()
{
	return freelist_count;
}

static inline int get_fd(stateid4 stateid, nfs_fh4 object, char *path)
{
	int cur_fd = -1;

	cur_fd = getfdnum();
	if (cur_fd < 0) {
		/* This is not possible because open call is sent to server only
		 * if freecount is greater than 0 */
		assert(0);
	}

	assert(fd_list[cur_fd].fd < 0);

	fd_list[cur_fd].fd = cur_fd;
	memcpy(&fd_list[cur_fd].stateid, &stateid, sizeof(stateid4));
	memcpy(&fd_list[cur_fd].fh, &object, sizeof(nfs_fh4));

	if (path != NULL) {
		fd_list[cur_fd].path = malloc(strlen(path) + 1);
		/* Check malloc failure */

		strncpy(fd_list[cur_fd].path, path, strlen(path) + 1);
	}

	freelist_count -= 1;
	return cur_fd;
}

static inline int freefd(int fd)
{
	if (fd < 0 || fd > MAX_FD) {
		/* Maybe assert()?? */
		/* Add error logs too */
		return -1;
	}

	if (fd_list[fd].fd < 0) {
		/* Add error logs too */
		return -1;
	}

	if (fd_list[fd].fd != fd) {
		/* Add error logs too */
		/* Implementation mistake, client has nothing to do with this */
		assert(0);
	}

	/* We have a valid fd that needs to be closed */

	if (fd_list[fd].path != NULL) {
		free(fd_list[fd].path);
	}

	fd_list[fd].path = NULL;
	fd_list[fd].fd = -1;

	freelist_tail %= MAX_FD;
	free_fdlist[freelist_tail++] = fd;
	freelist_count += 1;

	return 0;
}

bool readdir_reply(const char *name, void *dir_state, fsal_cookie_t cookie);

#ifdef __cplusplus
}
#endif


#endif // __TC_NFS4_UTIL_H__
