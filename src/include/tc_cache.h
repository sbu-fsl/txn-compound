/**
 * Cache API of NFS Transactional Compounds (TC).
 */
#ifndef __TC_CACHE_H__
#define __TC_CACHE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "tc_api.h"

/**
 * Initialize tc cache.
 * this will initialize the data structure for cache (will go with hash table
 * implementation for initial stage, as suggested by you)
 * @return 0 if the initialization is successful, or a negative error code.
 *
 * NEED TO DISCUSS the point from where init_tc_cache has to be called.
 * If it is to be called from pxy_create_export, then i will have to add
 * additional field for 'export_id' in every API mentioned below.
 */
int init_tc_cache();

enum cache_lookup_result {
  NOT_FOUND = 0,
  FRONT_MATCH = 1,
  BACK_MATCH = 2,
  FULL_MATCH = 3,
  MIDDLE_MATCH = 4,
};

/**
 * Lookup Cache for a given range of a file.
 *
 * @param file_path [in] key to lookup, should be an absolute full path
 * @param offset    [in] offset within the file
 * @param length    [in] bytes to read from the offset
 * @param buf       [out] buffer to get cached data in case of FULL_MATCH(as of now), else NULL
 *                          memory for buf has to be allocated by the caller
 * @param cached_offset [out] offset of the cached portion of the request
 * @param cached_length [out] bytes cached
 *
 * @return
 *    NOT_FOUND if the requested data are not found in the cache,
 *    FULL_MATCH if all the requested data are found with exact offset & length,
 *    or a negative error code.
 *    BACK_MATCH if the back part of the requested data are found,
 *    FULL_MATCH if all the requested data are found,
 *    MIDDLE_MATCH if a middle portion of the requested data are found,
 *    or a negative error code.
 *
 * NEXT:
 * 1. allow partial cache hit (FRONT_MATCH / END_MATCH).
 *      planning to implement only front / end match, need to discuss
 *      the feasibility of middle range match
 *      will add 2 more parameters in case of partial match
 *      a) cached_offset
 *      b) cached_length
 * 2. a zero length support to check if any part of the file is cached.
 *
 * NEED TO DISCUSS THE BEHAVIOUR IN FOLLOWING CASES
 * 1. Should i validate the cache at the time of lookup?
 *      If yes, need additional parameter.
 * 2. a separate functionality for validation of cached page?
 * 3. In case of revalidation, should it re validate all the
 *      entries related to particular file or would it be
 *      byte-range wise validation?
 *
 * NOTE: currently, only NOT_FOUND and FULL_MATCH are supported.
 * 3. We need cache revalidation, and that requires us to also keep file
 * meta-data in the cache.  The meta-data should include file size and file
 * modify time.
 *
 */
int lookup_cache(const const* file_path,
                 size_t offset,
                 size_t length,
                 char* buf,
                 size_t* cached_offset,
                 size_t* cached_length);


/**
 * Insert a byte range of a file into the cache.
 * @param file_path [in] should be absolute full path
 * @param offset    [in] the offset of the byte range
 * @param length    [in] the length of the byte range
 * @param buf       [in] the data buffer of the byte range
 * @return 0 if the insertion is successful, or a negative error code.
 *
 * Thinking about meta data of a file to be saved while insertion
 * which would be utilized for validation (eg: mtime?)
 *
 * Ming:
 * 1. Yes, we need mtime.  Please add that.
 * 2. Also, we need to cache file meta-data as well, and we need to add that.
 */
int insert_into_cache(const char *file_path, size_t offset, size_t length,
		      const char *buf);


/**
 * Insert directory entires into the cache.
 *
 * @param dir_path [in] parent path
 * @param children [in] children directory entries to be inserted
 * @param count    [in] # of entires in the children array
 * @param mtime_ns [in] modification time of the directory in nano-second
 * @param total_count [in] total number of children entries in the directory
 */
int insert_dir_entries(const char *dir_path,
		       const struct tc_attrs *children,
		       int count,
		       uint64_t mtime_ns,
		       int total_count);

/**
 * Delete all the existing cache of mentioned file.
 * @param file_path [in] should be an absolute full path.
 * @return 0 if the deletion is successful, or a negative error code.
 *
 * NEED TO DISCUSS the point from where to call this API.
 * Should be useful when a file gets deleted.
 *
 */
int delete_cache(const const* file_path);


/**
 * Destroy cache.
 */
void destroy_tc_cache();


#ifdef __cplusplus
}
#endif

#endif // __TC_CACHE_H__
