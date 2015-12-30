/* User header file for exported tc features */

#include "export_mgr.h"
#include "ganesha_list.h"
#include <stdlib.h>

#ifdef __cplusplus
#define CONST const
extern "C" {
#else
#define CONST
#endif

struct tc_iovec
{
	const char *CONST path;		/* IN: the file path */
	CONST size_t offset;		/* IN: read/write offset */

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
	void *CONST data;

	unsigned int is_creation : 1;  /* IN: create file if not exist? */
	unsigned int is_failure : 1;   /* OUT: is this I/O a failure? */
	unsigned int is_eof : 1;       /* OUT: does this I/O reach EOF? */
};

/* Multiple reads for single file */
fsal_status_t tcread_v(struct gsh_export *export, struct tc_iovec *arg,
		       int read_count, bool isTransaction);
/* Multiple writes for single file
fsal_status_t tcwrite_s(struct gsh_export *export,
			struct user_tcwrite_args *arg, int write_count);
*/
/* Single write for multiple files
fsal_status_t tcwrite_m(struct gsh_export *export,
			struct user_tcwrite_args *arg, int file_count);
*/
