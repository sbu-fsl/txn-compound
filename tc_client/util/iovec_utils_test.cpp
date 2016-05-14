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

#include "iovec_utils.h"

#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "tc_helper.h"

using std::vector;

constexpr size_t operator"" _KB(unsigned long long a) { return a << 10; }
constexpr size_t operator"" _MB(unsigned long long a) { return a << 20; }
constexpr size_t operator"" _GB(unsigned long long a) { return a << 30; }

TEST(IovecUtils, SplitOneBigIovec)
{
	const char *PATH = "SplitOneBigIovec.dat";
	tc_iovec big_iov;
	const size_t LEN = 5_MB;
	char *buf = (char *)malloc(LEN);

	tc_iov4creation(&big_iov, PATH, LEN, buf);
	struct tc_iov_array iova = TC_IOV_ARRAY_INITIALIZER(&big_iov, 1);

	vector<size_t> size_limits {64_KB, 128_KB, 256_KB, 512_KB, 1_GB};
	for (size_t limit : size_limits) {
		int nparts;
		auto parts = tc_split_iov_array(&iova, limit, &nparts);
		size_t off = big_iov.offset;
		for (int i = 0; i < nparts; ++i) {
			size_t cpd_size = 0;
			for (int s = 0; s < parts[i].size; ++s) {
				EXPECT_EQ(off + cpd_size,
					  parts[i].iovs[s].offset);
				cpd_size += parts[i].iovs[s].length;
				EXPECT_EQ((i == 0 && s == 0),
					  parts[i].iovs[s].is_creation);
				EXPECT_TRUE(tc_cmp_file(
				    &big_iov.file, &parts[i].iovs[s].file));
			}
			EXPECT_LE(cpd_size, limit);
			off += cpd_size;
		}
		EXPECT_EQ(off, big_iov.offset + big_iov.length);
		EXPECT_TRUE(tc_restore_iov_array(&iova, &parts, nparts));
		EXPECT_EQ(NULL, parts);
	}
}

//TEST(IovecUtils, ShortRead)
//TEST(IovecUtils, SetEofCorrectly)
//TEST(IovecUtils, AdjacentOffsetButDifferentFiles)
//TEST(IovecUtils, InputOverlaps)
