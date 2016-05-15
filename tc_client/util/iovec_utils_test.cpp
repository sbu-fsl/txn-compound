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

	vector<size_t> size_limits {64_KB, 128_KB, 256_KB, 512_KB, 1_MB};
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

	free(buf);
}

TEST(IovecUtils, SmallCpdsAreNotSplit)
{
	struct tc_iovec iovs[5];

	for (int i = 0; i < 5; ++i) {
		tc_iov2fd(iovs + i, (1 << 30) + i, 0, 1024, new char[1024]);
	}

	for (int n = 1; n <= 5; ++n) {
		struct tc_iov_array iova = TC_IOV_ARRAY_INITIALIZER(iovs, n);
		int nparts;
		auto parts = tc_split_iov_array(&iova, 1_MB, &nparts);
		EXPECT_EQ(1, nparts);
		for (int i = 0; i < iova.size; ++i) {
			EXPECT_EQ(0, memcmp(iova.iovs + i, parts[0].iovs + i,
					    sizeof(struct tc_iovec)));
		}
		EXPECT_TRUE(tc_restore_iov_array(&iova, &parts, nparts));
	}

	for (int i = 0; i < 5; ++i) {
		delete[] iovs[i].data;
	}
}

TEST(IovecUtils, EofIsSetCorrectly)
{
	struct tc_iovec iovs[2];
	iovs[0].is_eof = iovs[1].is_eof = false;
	tc_iov2fd(iovs + 0, (1 << 30) + 1, 0, 512_KB, new char[512_KB]);
	tc_iov2fd(iovs + 1, (1 << 30) + 2, 0, 1_MB, new char[1_MB]);

	struct tc_iov_array iova = TC_IOV_ARRAY_INITIALIZER(iovs, 2);
	int nparts = 0;
	auto parts = tc_split_iov_array(&iova, 1_MB, &nparts);
	EXPECT_EQ(2, nparts);

	EXPECT_EQ(2, parts[0].size);
	EXPECT_EQ(1, parts[1].size);
	parts[0].iovs[0].is_eof = true;
	parts[1].iovs[0].is_eof = true;

	EXPECT_TRUE(tc_restore_iov_array(&iova, &parts, nparts));
	EXPECT_TRUE(iovs[0].is_eof);
	EXPECT_TRUE(iovs[1].is_eof);

	delete[] iovs[0].data;
	delete[] iovs[1].data;
}

TEST(IovecUtils, AdjacentOffsetsOfDifferentFilesAreNotMerged)
{
	struct tc_iovec iovs[3];
	tc_iov2fd(iovs + 0, (1 << 30) + 1, 0, 512_KB, new char[512_KB]);
	tc_iov2fd(iovs + 1, (1 << 30) + 2, 512_KB, 512_KB, new char[512_KB]);
	tc_iov2fd(iovs + 2, (1 << 30) + 3, 1_MB, 512_KB, new char[512_KB]);

	struct tc_iov_array iova = TC_IOV_ARRAY_INITIALIZER(iovs, 3);
	int nparts;
	auto parts = tc_split_iov_array(&iova, 1_MB, &nparts);

	EXPECT_TRUE(tc_restore_iov_array(&iova, &parts, nparts));
	EXPECT_EQ(512_KB, iovs[0].length);
	EXPECT_EQ(512_KB, iovs[1].length);
	EXPECT_EQ(512_KB, iovs[2].length);

	delete[] iovs[0].data;
	delete[] iovs[1].data;
	delete[] iovs[2].data;
}

TEST(IovecUtils, HandleShortRdWr)
{
	struct tc_iovec iovs[3];
	tc_iov2fd(iovs + 0, (1 << 30) + 1, 0, 512_KB, new char[512_KB]);
	tc_iov2fd(iovs + 1, (1 << 30) + 2, 512_KB, 1_MB, new char[1_MB]);
	tc_iov2fd(iovs + 2, (1 << 30) + 3, 1_MB, 1_MB, new char[1_MB]);

	struct tc_iov_array iova = TC_IOV_ARRAY_INITIALIZER(iovs, 3);
	int nparts;
	auto parts = tc_split_iov_array(&iova, 1_MB, &nparts);

	EXPECT_EQ(3, nparts);
	parts[0].iovs[0].length = 256_KB;
	parts[1].iovs[0].length -= 1_KB;
	parts[1].iovs[0].is_eof = true;
	parts[2].iovs[parts[2].size - 1].length -= 256_KB;

	EXPECT_TRUE(tc_restore_iov_array(&iova, &parts, nparts));
	EXPECT_EQ(256_KB, iovs[0].length);
	EXPECT_EQ(1023_KB, iovs[1].length);
	EXPECT_TRUE(iovs[1].is_eof);
	EXPECT_EQ(768_KB, iovs[2].length);

	delete[] iovs[0].data;
	delete[] iovs[1].data;
	delete[] iovs[2].data;
}

TEST(IovecUtils, HandleOverlappedIovecs)
{
	struct tc_iovec iovs[2];
	tc_iov2fd(iovs + 0, (1 << 30) + 1, 0, 256_KB, new char[256_KB]);
	tc_iov2fd(iovs + 1, (1 << 30) + 1, 128_KB, 256_KB, new char[256_KB]);

	struct tc_iov_array iova = TC_IOV_ARRAY_INITIALIZER(iovs, 2);
	int nparts;
	auto parts = tc_split_iov_array(&iova, 1_MB, &nparts);

	EXPECT_TRUE(tc_restore_iov_array(&iova, &parts, nparts));
	EXPECT_EQ(256_KB, iovs[0].length);
	EXPECT_EQ(256_KB, iovs[1].length);

	delete[] iovs[0].data;
	delete[] iovs[1].data;
}
