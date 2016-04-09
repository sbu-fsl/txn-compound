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
 */

#include <string.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <utility>
#include <string>
#include <vector>

#include "util/path_utils.h"

TEST(PathUtilsTest, nomalizeTest) {
	char path[1024];
	auto Expect = [&path](const char *input, const char *expected) {
		int ret = tc_path_nomalize(input, path, 1024);
		ASSERT_GT(ret, 0) << "failed to nomalize \"" << input << "\"\n";
		EXPECT_STREQ(expected, path) << input << " is normalized to "
			<< path << " instead of " << expected;
	};

	Expect("/", "/");
	Expect("//", "/");
	Expect("/foo/bar/", "/foo/bar");
	Expect("/foo/../bar/", "/bar");
	Expect("/foo/../../../", "/");
	Expect("foo/..", ".");

	EXPECT_EQ(-1, tc_path_nomalize("foo/../../", path, 1024));

	// Test in-place nomalize
	strcpy(path, "/foo/bar/../../baz");
	Expect(path, "/baz");
}
