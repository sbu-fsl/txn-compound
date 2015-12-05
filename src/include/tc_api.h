/**
 * Client API of NFS Transactional Compounds (TC).
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
 * Read from one or more files.
 *
 * @n: the length of the iovec array
 * @reads: the iovec array.  "path" of the first array element must not be
 * NULL; a NULL "path" of any other array element means using the same "path"
 * of the preceding array element.
 */
int tc_readv(int n, struct tc_iovec *reads);

/**
 * Write to one or more files.
 *
 * @n: the length of the iovec array
 * @reads: the iovec array.  "path" of the first array element must not be
 * NULL; a NULL "path" of any other array element means using the same "path"
 * of the preceding array element.
 */
int tc_writev(int n, struct tc_iovec *writes);

#ifdef __cplusplus
#undef CONST
}
#else
#undef CONST
#endif
