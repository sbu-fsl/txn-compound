/**
 * Client API of NFS Transactional Compounds (TC).
 *
 * Functions with "tc_" are general API, whereas functions with "tx_" are API
 * with transaction support.
 */
#include <stdlib.h>

#ifdef __cplusplus
#define CONST const
extern "C" {
#else
#define CONST
#endif

/**
 * Represents an I/O vector of a file.
 *
 * The fileds have different meaning depending the operation is read or write.
 * Most often, clients allocate an array of this struct.
 */
struct tc_iovec {
	const char *CONST path;    /* IN: the file path */
	CONST size_t offset;       /* IN: read/write offset */

	/**
	 * IN:  # of bytes of requested read/write
	 * OUT: # of bytes successfully read/written
	 */
	size_t length;

	/**
	 * This data buffer should always be allocated by caller for either
	 * read or write, and the length of the buffer should be indicated by
	 * "length".
	 *
	 * IN:  data requested to be written
	 * OUT: data successfully read
	 */
	void *CONST data;

	unsigned int is_creation : 1;  /* IN: create file if not exist? */
	unsigned int is_failure : 1;   /* OUT: is this I/O a failure? */
	unsigned int is_eof : 1;       /* OUT: does this I/O reach EOF? */
};

/**
 * Result of a TC operation.
 *
 * When transaction is not enabled, compound processing stops upon the first
 * failure.
 */
struct tc_res {
	bool okay;  /* no error */
	int index;  /* index of the first failed operation */
	int errno;  /* error number of the failed operation */
};

/**
 * Read from one or more files.
 *
 * @n: the length of the iovec array
 * @reads: the iovec array.  "path" of the first array element must not be
 * NULL; a NULL "path" of any other array element means using the same "path"
 * of the preceding array element.
 */
tc_res tc_readv(int n, struct tc_iovec *reads, bool is_transaction);

static inline bool tx_readv(int n, struct tc_iovec *reads) {
	tc_res res = tc_readv(n, reads, true);
	return res.okay;
}

/**
 * Write to one or more files.
 *
 * @n: the length of the iovec array
 * @reads: the iovec array.  "path" of the first array element must not be
 * NULL; a NULL "path" of any other array element means using the same "path"
 * of the preceding array element.
 */
tc_res tc_writev(int n, struct tc_iovec *writes, bool is_transaction);

static inline bool tx_writev(int n, struct tc_iovec *writes) {
	tc_res res = tc_writev(n, writes, true);
	return res.okay;
}

/**
 * The bitmap indicating the presence of file attributes.
 */
struct tc_attrs_masks {
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
struct tc_attrs {
	const char *path;   /* file path */
	struct tc_attrs_masks masks;
	mode_t mode;     /* protection */
	size_t size;     /* file size, in bytes */
	nlink_t nlink;   /* number of hard links */
	uid_t uid;
	gid_t gid;
	dev_t rdev;
	time_t atime;
	time_t mtime;
	time_t ctime;
};

/**
 * Get attributes of file objects.
 *
 * @n: the length of the tc_attrs array
 * @attrs: array of attributes to get.
 */
tc_res tc_getattrs(int n, struct tc_attrs* attrs, is_transaction);

static inline bool tx_getattrs(int n, struct tc_attrs* attrs) {
	tc_res res = tc_getattrs(n, attrs);
	return res.okay;
}

/**
 * Set attributes of file objects.
 *
 * @n: the length of the tc_attrs array
 * @attrs: array of attributes to set.
 */
int tc_setattrs(int n, struct tc_attrs* attrs);

static inline bool tx_setattrs(int n, struct tc_attrs* attrs) {
	tc_res res = tc_setattrs(n, attrs);
	return res.okay;
}

#ifdef __cplusplus
#undef CONST
}
#else
#undef CONST
#endif
