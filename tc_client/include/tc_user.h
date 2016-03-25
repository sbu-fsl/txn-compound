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

/*
 * Result of a TC operation.
 *
 * When transaction is not enabled, compound processing stops upon the first
 * failure.
 */
typedef struct tc_res
{
	bool okay;   /* no error */
	int index;   /* index of the first failed operation */
	int err_no;  /* error number of the failed operation */
} tc_res;

/* 
 * Initialize export structures and other functions
 * User has to call this before using tc functions
 *
 * export_id - Export id mentioned in the conf file
 *
 * Returns
 * 0 for success
 * -1 for failure
 */
int tc_init(uint16_t export_id);

/*
 * Deinit the export which was initialized previously
 * Will always succeed
 */
void tc_deinit();

/* User has to set op_ctx->export to the right export for this to work */
struct tc_res tcread_v(struct tc_iovec *arg, int read_count,
		       bool isTransaction);

/* User has to set op_ctx->export to the right export for this to work */
struct tc_res tcwrite_v(struct tc_iovec *arg, int write_count,
			bool isTransaction);

