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

#define EXPECT_OKAY(x) EXPECT_EQ(x, SECNFS_OKAY)

#define EXPECT_SAME(buf_a, buf_b, len) EXPECT_EQ(memcmp(buf_a, buf_b, len), 0)

secnfs::Context *NewContextWithProxies(int nproxy);

secnfs_info_t *NewSecnfsInfo(int nproxy);

};

#endif
