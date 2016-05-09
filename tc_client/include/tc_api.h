/**
 * Copyright (C) Stony Brook University 2016
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * Client API of NFS Transactional Compounds (TC).
 *
 * Functions with "tc_" are general API, whereas functions with "tx_" are API
 * with transaction support.
 */
#ifndef __TC_API_H__
#define __TC_API_H__

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * Initialize tc_client
 * log_path - Location of the log file
 * config_path - Location of the config file
 * export_id - Export id of the export configured in the conf file
 *
 * This returns fsal_module pointer to tc_client module
 * If tc_client module does not exist, it will return NULL
 *
 * Caller of this function should call tc_deinit() after use
 */
void *tc_init(const char *config_path, const char *log_path,
	      uint16_t export_id);

/*
 * Free the reference to module and op_ctx
 * Should be called if tc_init() was called previously
 *
 * This will always succeed
 */
void tc_deinit(void *module);

enum TC_FILETYPE {
	TC_FILE_DESCRIPTOR = 1,
	TC_FILE_PATH,
	TC_FILE_HANDLE,
	TC_FILE_CURRENT,
	TC_FILE_SAVED,
};

#define TC_FD_NULL -1
#define TC_FD_CWD -2
#define TC_FD_ABS -3

/* See http://lxr.free-electrons.com/source/include/linux/exportfs.h */
#define FILEID_NFS_FH_TYPE 0x1001

/**
 * "type" is one of the five file types; "fd" and "path_or_handle" depend on
 * the file type:
 *
 *	1. When "type" is TC_FILE_DESCRIPTOR, "fd" identifies the file we are
 *	operating on.
 *
 *	2. When "type" is TC_FILE_PATH, "fd" is the base file descriptor, and
 *	"path_or_handle" is the file path.  The file is identified by resolving
 *	the path relative to "fd".  In this case, "fd" has two special values:
 *	(a) TC_FDCWD which means the current working directory, and
 *	(b) TC_FDABS which means the "path_or_handle" is an absolute path.
 *
 *	3. When "type" is TC_FILE_HANDLE, "fd" is "mount_fd", and
 *	"path_or_handle" points to "struct file_handle".  We expand the "type"
 *	of "struct file_handle" to include FILEID_NFS_FH_TYPE.
 *
 *	4. When "type" is TC_FILE_CURRENT, the "current filehandle" on the NFS
 *	server side is used.  "fd" and "path" are ignored.
 *
 *	5. When "type" is TC_FILE_SAVED, the "saved filehandle" on the NFS
 *	server side is used.  "fd" and "path" are ignored.
 *
 * See http://man7.org/linux/man-pages/man2/open_by_handle_at.2.html
 */
typedef struct _tc_file
{
	int type;

	int fd;

	union
	{
		const char *path;
		const struct file_handle *handle;
	}; /* path_or_handle */
} tc_file;

static inline tc_file tc_file_from_path(const char *pathname) {
	tc_file tf;

	assert(pathname);
	tf.type = TC_FILE_PATH;
	tf.fd = pathname[0] == '/' ? TC_FD_ABS : TC_FD_CWD;
	tf.path = pathname;

	return tf;
}

static inline tc_file tc_file_from_fd(int fd) {
	tc_file tf;

	tf.type = TC_FILE_DESCRIPTOR;
	tf.fd = fd;
	tf.path = NULL;

	return tf;
}

static inline tc_file tc_file_current(void)
{
	tc_file tf;

	tf.type = TC_FILE_CURRENT;
	tf.fd = -1;     /* poison */
	tf.path = NULL; /* poison */

	return tf;
}

/**
 * Create a TC file relative to current FH.
 */
static inline tc_file tc_file_from_cfh(const char *relpath) {
	tc_file tf;

	if (relpath && relpath[0] == '/') {
		return tc_file_from_path(relpath);
	}
	
	tf.type = TC_FILE_CURRENT;
	tf.fd = -1;	/* poison */
	tf.path = relpath;

	return tf;
}

/**
 * Open a tc_file using path.  Similar to "openat(2)".
 *
 * NOTE: It is not necessary that a tc_file have to be open before reading
 * from/writing to it.  We recommend using tc_readv() and tc_writev() to
 * implicitly open a file when necessary.
 */
tc_file* tc_open_by_path(int dirfd, const char *pathname, int flags,
			mode_t mode);

static inline tc_file* tc_open(const char *pathname, int flags, mode_t mode)
{
	return tc_open_by_path(AT_FDCWD, pathname, flags, mode);
}

/**
 * Open a tc_file using file handle.  Similar to "open_by_handle_at(2)".
 */
tc_file tc_open_by_handle(int mount_fd, struct file_handle *fh, int flags);

/**
 * Close a tc_file if necessary.
 */
int tc_close(tc_file *tcf);

/**
 * Change current work directory to "path".
 *
 * Return 0 on success and a negative error number in case of failure.
 */
int tc_chdir(const char *path);

/**
 * Returns current working directory.
 *
 * The caller owns the returned buffer and is responsible for freeing it.
 */
char *tc_getcwd(void);

/**
 * A special offset that is the same as the file size.
 */
#define TC_OFFSET_END (SIZE_MAX-1)
/**
 * A special offset indicates the current offset of the file descriptor.
 */
#define TC_OFFSET_CUR (SIZE_MAX)

/**
 * Represents an I/O vector of a file.
 *
 * The fields have different meaning depending the operation is read or write.
 * Most often, clients allocate an array of this struct.
 */
struct tc_iovec
{
	tc_file file;
	size_t offset; /* IN: read/write offset */

	/**
	 * IN:  # of bytes of requested read/write
	 * OUT: # of bytes successfully read/written
	 */
	size_t length;

	/**
	 * This data buffer should always be allocated by caller for either
	 * read or write, and the length of the buffer should be indicated by
	 * the "length" field above.
	 *
	 * IN:  data requested to be written
	 * OUT: data successfully read
	 */
	void *data;

	unsigned int is_creation : 1; /* IN: create file if not exist? */
	unsigned int is_failure : 1;  /* OUT: is this I/O a failure? */
	unsigned int is_eof : 1;      /* OUT: does this I/O reach EOF? */
	unsigned int is_write_stable : 1;   /* IN/OUT: stable write? */
};

/**
 * Result of a TC operation.
 *
 * When transaction is not enabled, compound processing stops upon the first
 * failure.
 */
typedef struct _tc_res
{
	bool okay;  /* no error */
	int index;  /* index of the first failed operation */
	int err_no; /* error number of the failed operation */
} tc_res;

static inline tc_res tc_failure(int i, int err) {
	tc_res res;
	res.okay = false;
	res.index = i;
	res.err_no = err;
	return res;
}

tc_file *tc_openv(const char **paths, int count, int *flags, mode_t *modes);

tc_file *tc_openv_simple(const char **paths, int count, int flags, mode_t mode);

tc_res tc_closev(tc_file *files, int count);

/**
 * Reposition read/write file offset.
 * REQUIRE: tcf->type == TC_FILE_DESCRIPTOR
 */
off_t tc_fseek(tc_file *tcf, off_t offset, int whence);

/**
 * Read from one or more files.
 *
 * @reads: the tc_iovec array of read operations.  "path" of the first array
 * element must not be NULL; a NULL "path" of any other array element means
 * using the same "path" of the preceding array element.
 * @count: the count of reads in the preceding array
 * @is_transaction: whether to execute the compound as a transaction
 */
tc_res tc_readv(struct tc_iovec *reads, int count, bool is_transaction);

static inline bool tx_readv(struct tc_iovec *reads, int count)
{
	tc_res res = tc_readv(reads, count, true);
	return res.okay;
}

/**
 * Write to one or more files.
 *
 * @writes: the tc_iovec array of write operations.  "path" of the first array
 * element must not be NULL; a NULL "path" of any other array element means
 * using the same "path"
 * @count: the count of writes in the preceding array
 * @is_transaction: whether to execute the compound as a transaction
 */
tc_res tc_writev(struct tc_iovec *writes, int count, bool is_transaction);

static inline bool tx_writev(struct tc_iovec *writes, int count)
{
	tc_res res = tc_writev(writes, count, true);
	return res.okay;
}

/**
 * The bitmap indicating the presence of file attributes.
 */
struct tc_attrs_masks
{
	unsigned int has_mode : 1;  /* protection flags */
	unsigned int has_size : 1;  /* file size, in bytes */
	unsigned int has_nlink : 1; /* number of hard links */
	unsigned int has_uid : 1;   /* user ID of owner */
	unsigned int has_gid : 1;   /* group ID of owner */
	unsigned int has_rdev : 1;  /* device ID of block or char special
				   files */
	unsigned int has_atime : 1; /* time of last access */
	unsigned int has_mtime : 1; /* time of last modification */
	unsigned int has_ctime : 1; /* time of last status change */
};

/**
 * File attributes.  See stat(2).
 */
struct tc_attrs
{
	tc_file file;
	struct tc_attrs_masks masks;
	mode_t mode;   /* protection */
	size_t size;   /* file size, in bytes */
	nlink_t nlink; /* number of hard links */
	uid_t uid;
	gid_t gid;
	dev_t rdev;
	struct timespec atime;
	struct timespec mtime;
	struct timespec ctime;
};

static inline void tc_attrs_set_mode(struct tc_attrs *attrs, mode_t mode)
{
	attrs->mode = mode;
	attrs->masks.has_mode = true;
}

static inline void tc_attrs_set_size(struct tc_attrs *attrs, size_t size)
{
	attrs->size = size;
	attrs->masks.has_size = true;
}

static inline void tc_attrs_set_uid(struct tc_attrs *attrs, size_t uid)
{
	attrs->uid = uid;
	attrs->masks.has_uid = true;
}

static inline void tc_attrs_set_gid(struct tc_attrs *attrs, size_t gid)
{
	attrs->gid = gid;
	attrs->masks.has_gid = true;
}

static inline void tc_attrs_set_atime(struct tc_attrs *attrs,
				      struct timespec atime)
{
	attrs->atime = atime;
	attrs->masks.has_atime = true;
}

static inline void tc_attrs_set_mtime(struct tc_attrs *attrs,
				      struct timespec mtime)
{
	attrs->mtime = mtime;
	attrs->masks.has_mtime = true;
}

static inline void tc_set_up_creation(struct tc_attrs *newobj, const char *name,
				      mode_t mode)
{
	newobj->file = tc_file_from_path(name);
	memset(&newobj->masks, 0, sizeof(struct tc_attrs_masks));
	newobj->masks.has_mode = true;
	newobj->mode = mode;
	newobj->masks.has_uid = true;
	newobj->uid = geteuid();
	newobj->masks.has_gid = true;
	newobj->gid = getegid();
}

static inline void tc_attrs_mask_set(struct tc_attrs_masks *masks)
{
	masks->has_mode = true;
	masks->has_size = true;
	masks->has_nlink = true;
	masks->has_uid = true;
	masks->has_gid = true;
	masks->has_rdev = true;
	masks->has_atime = true;
	masks->has_mtime = true;
	masks->has_ctime = true;
}

/**
 * Get attributes of file objects.
 *
 * @attrs: array of attributes to get
 * @count: the count of tc_attrs in the preceding array
 * @is_transaction: whether to execute the compound as a transaction
 */
tc_res tc_getattrsv(struct tc_attrs *attrs, int count, bool is_transaction);

static inline bool tx_getattrsv(struct tc_attrs *attrs, int count)
{
	tc_res res = tc_getattrsv(attrs, count, true);
	return res.okay;
}

/**
 * Set attributes of file objects.
 *
 * @attrs: array of attributes to set
 * @count: the count of tc_attrs in the preceding array
 * @is_transaction: whether to execute the compound as a transaction
 */
tc_res tc_setattrsv(struct tc_attrs *attrs, int count, bool is_transaction);

static inline bool tx_setattrsv(struct tc_attrs *attrs, int count)
{
	tc_res res = tc_setattrsv(attrs, count, true);
	return res.okay;
}

/**
 * List the content of a directory.
 *
 * @dir [IN]: the path of the directory to list
 * @masks [IN]: masks of attributes to get for listed objects
 * @max_count [IN]: the maximum number of count to list
 * @contents [OUT]: the pointer to the array of files/directories in the
 * directory.  The array and the paths in the array will be allocated
 * internally by this function; the caller is responsible for releasing the
 * memory, probably by using tc_free_attrs().
 */
tc_res tc_listdir(const char *dir, struct tc_attrs_masks masks, int max_count,
		  struct tc_attrs **contents, int *count);

/**
 * Callback of tc_listdirv().
 *
 * @entry [IN]: the current directory entry listed
 * @dir [IN]: the parent directory of @entry as provided in the first argument
 * of tc_listdirv().
 * @cbarg [IN/OUT]: any extra user arguments or context of the callback.
 *
 * Return whether tc_listdirv() should continue the processing or stop.
 */
typedef bool (*tc_listdirv_cb)(const struct tc_attrs *entry, const char *dir,
			       void *cbarg);
/**
 * List the content of the specified directories.
 *
 * @dirs: the array of directories to list
 * @count: the length of "dirs"
 * @masks: the attributes to retrieve for each listed entry
 * @max_entries: the max number of entry to list; 0 means infinite
 * @cb: the callback function to be applied to each listed entry
 */
tc_res tc_listdirv(const char **dirs, int count, struct tc_attrs_masks masks,
		   int max_entries, tc_listdirv_cb cb, void *cbarg,
		   bool is_transaction);

/**
 * Free an array of "tc_attrs".
 *
 * @attrs [IN]: the array to be freed
 * @count [IN]: the length of the array
 * @free_path [IN]: whether to free the paths in "tc_attrs" as well.
 */
static inline void tc_free_attrs(struct tc_attrs *attrs, int count,
				 bool free_path)
{
	int i;
	if (free_path) {
		for (i = 0; i < count; ++i) {
			if (attrs[i].file.type == TC_FILE_PATH)
				free((char *)attrs[i].file.path);
			else if (attrs[i].file.type == TC_FILE_HANDLE)
				free((char *)attrs[i].file.handle);
		}
	}
	free(attrs);
}

typedef struct tc_file_pair
{
	tc_file src_file;
	tc_file dst_file;
} tc_file_pair;

/**
 * Rename the file from "src_path" to "dst_path" for each of "pairs".
 *
 * @pairs: the array of file pairs to be renamed
 * @count: the count of the preceding "tc_file_pair" array
 * @is_transaction: whether to execute the compound as a transaction
 */
tc_res tc_renamev(struct tc_file_pair *pairs, int count, bool is_transaction);

static inline bool tx_renamev(tc_file_pair *pairs, int count)
{
	tc_res res = tc_renamev(pairs, count, true);
	return res.okay;
}

tc_res tc_removev(tc_file *files, int count, bool is_transaction);

static inline bool tx_removev(tc_file *files, int count)
{
	tc_res res = tc_removev(files, count, true);
	return res.okay;
}

/**
 * Create one or more directories.
 *
 * @dirs [IN/OUT]: the directories and their attributes (mode, uid, gid) to be
 * created.  Other attributes (timestamps etc.) of the newly created
 * directories will be returned on success.
 * @count [IN]: the count of the preceding "dirs" array
 * @is_transaction [IN]: whether to execute the compound as a transaction
 */
tc_res tc_mkdirv(struct tc_attrs *dirs, int count, bool is_transaction);

static inline bool tx_mkdirv(struct tc_attrs *dirs, int count,
			     bool is_transaction)
{
	tc_res res = tc_mkdirv(dirs, count, is_transaction);
	return res.okay;
}

struct tc_extent_pair
{
	const char *src_path;
	const char *dst_path;
	size_t src_offset;
	size_t dst_offset;
	size_t length;
};

/**
 * Copy the file from "src_path" to "dst_path" for each of "pairs".
 *
 * @pairs: the array of file extent pairs to copy
 * @count: the count of the preceding "tc_extent_pair" array
 * @is_transaction: whether to execute the compound as a transaction
 */
tc_res tc_copyv(struct tc_extent_pair *pairs, int count, bool is_transaction);

static inline bool tx_copyv(struct tc_extent_pair *pairs, int count)
{
	tc_res res = tc_copyv(pairs, count, true);
	return res.okay;
}

/**
 * Application data blocks (ADB).
 *
 * See https://tools.ietf.org/html/draft-ietf-nfsv4-minorversion2-39#page-60
 */
struct tc_adb
{
	const char *path;

	/**
	 * The offset within the file the ADB blocks should start.
	 */
	size_t adb_offset;

	/**
	 * size (in bytes) of an ADB block
	 */
	size_t adb_block_size;

	/**
	 * IN: requested number of ADB blocks to write
	 * OUT: number of ADB blocks successfully written.
	 */
	size_t adb_block_count;

	/**
	 * Relative offset within an ADB block to write then Application Data
	 * Block Number (ADBN).
	 *
	 * A value of UINT64_MAX means no ADBN to write.
	 */
	size_t adb_reloff_blocknum;

	/**
	 * The Application Data Block Number (ADBN) of the first ADB.
	 */
	size_t adb_block_num;

	/**
	 * Relative offset of the pattern within an ADB block.
	 *
	 * A value of UINT64_MAX means no pattern to write.
	 */
	size_t adb_reloff_pattern;

	/**
	 * Size and value of the ADB pattern.
	 */
	size_t adb_pattern_size;
	void *adb_pattern_data;
};

/**
 * Write Application Data Blocks (ADB) to one or more files.
 *
 * @patterns: the array of ADB patterns to write
 * @count: the count of the preceding pattern array
 * @is_transaction: whether to execute the compound as a transaction
 */
tc_res tc_write_adb(struct tc_adb *patterns, int count, bool is_transaction);

static inline bool tx_write_adb(struct tc_adb *patterns, int count)
{
	tc_res res = tc_write_adb(patterns, count, true);
	return res.okay;
}

/**
 * Create the specified directory and all its ancestor directories.
 * When "leaf" is NULL, "dir" is considered the full path of the target
 * directory; when "leaf" is not NULL, the parent of "dir" is the target
 * directory, and leaf will be set to the name of the leaf node.
 */
tc_res tc_ensure_dir(const char *dir, mode_t mode, slice_t *leaf);

#ifdef __cplusplus
}
#endif

#endif // __TC_API_H__
