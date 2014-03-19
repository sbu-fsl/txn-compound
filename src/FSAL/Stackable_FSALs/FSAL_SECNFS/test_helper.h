/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Helper for unit tests.
 */

#ifndef H_TEST_HELPER
#define H_TEST_HELPER

#include "secnfs.h"
#include "context.h"

namespace secnfs_test {

secnfs::Context *NewContextWithProxies(int nproxy);

secnfs_info_t *NewSecnfsInfo(int nproxy);

};

#endif
