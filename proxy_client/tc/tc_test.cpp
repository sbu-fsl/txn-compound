#include <errno.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "tc_api.h"

// Ensure the file does not exist before test.
static void RemoveFile(const char *path) {
	int r = unlink(path);
	EXPECT_TRUE(r == 0 || r == ENOENT);
}

TEST(tc_test, WritevCanCreateFiles) {
	const char* PATH = "/tmp/WritevCanCreateFiles.txt";
	const int N = 16;
	char data[N];
	tc_res res;
	struct tc_iovec write = {
		.path = PATH,
		.offset = 0,
		.length = N,
		.data = data,
		.is_creation = 1,
	};

	RemoveFile(PATH);

	res = tc_writev(&write, 1, false);
	EXPECT_TRUE(res.okay);

	struct tc_attrs_masks mask;
	mask.has_size = 1;
	mask.has_nlink = 1;
	struct tc_attrs attrs = {
		.path = PATH,
		.masks = mask,
	};

	res = tc_getattrsv(&attrs, 1, false);
	EXPECT_TRUE(res.okay);
	EXPECT_EQ(N, attrs.size);
	EXPECT_EQ(1, attrs.nlink);
}
