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
#include <math.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <random>
#include <string>

#include "common_types.h"

using std::string;
using std::vector;

TEST(BufTest, Basics) {
	buf_t *pbuf = new_buf(20);
	EXPECT_TRUE(pbuf);
	EXPECT_EQ(sizeof(buf_t), abs((size_t)pbuf - (size_t)(pbuf->data)));
	EXPECT_EQ(20, pbuf->capacity);
	EXPECT_EQ(0, pbuf->size);
	EXPECT_EQ(5, buf_append_str(pbuf, "abcde"));
	EXPECT_EQ(5, pbuf->size);
	EXPECT_EQ(5, buf_append_str(pbuf, "fghij"));
	EXPECT_EQ(5, buf_append_str(pbuf, "klmno"));
	EXPECT_EQ(5, buf_append_str(pbuf, "pqrst"));
	EXPECT_EQ(20, pbuf->size);
	EXPECT_EQ(-1, buf_append_str(pbuf, "u"));
	EXPECT_EQ(0, strncmp("abcdefghijklmnopqrstu", pbuf->data, pbuf->size));
	del_buf(pbuf);
}

TEST(BufTest, AutoBuf) {
	buf_t *abuf = new_auto_buf(5);
	EXPECT_EQ(5, abuf->capacity);
	EXPECT_EQ(0, abuf->size);
	EXPECT_EQ(5, buf_append_str(abuf, "abcde"));
	EXPECT_EQ(-1, buf_append_str(abuf, "x"));
	EXPECT_EQ(5, abuf->size);

	slice_t sl = asslice(abuf);
	EXPECT_EQ(5, sl.size);
	EXPECT_EQ(0, strncmp(sl.data, "abcde", sl.size));
}

TEST(SliceTest, Basics) {
	const char *msg = "foo-bar";
	slice_t s1 = mkslice(msg, strlen(msg));
	slice_t s2 = toslice(msg);
	EXPECT_EQ(s1.size, s2.size);
	EXPECT_EQ(0, strcmp(s1.data, s2.data));
}

static void test_bitset(bitset_t *bs, const std::string& tag)
{
	for (int i = 0; i < bs->size; ++i) {
		EXPECT_FALSE(bs_get(bs, i));
	}
	std::uniform_int_distribution<int> dist(0, bs->size - 1);
	std::mt19937 rng;
	rng.seed(8887);
	std::vector<bool> expected(bs->size, 0);
	const int M = bs->size * 3 / 4;
	for (int i = 0; i < M; ++i) {
		int pos = dist(rng);
		bs_set(bs, pos);
		expected[pos] = true;
	}
	for (int i = 0; i < bs->size; ++i) {
		EXPECT_EQ(bs_get(bs, i), expected[i])
		    << tag << " mismatch at position " << i;
	}
}

TEST(BitsetTest, Basics) {
	for (int N = 1; N <= 64; ++N) {
		bitset_t *bs = new_bitset(N);
		test_bitset(bs, string("basic-bitset-") + std::to_string(N));
		del_bitset(bs);
	}
}

TEST(BitsetTest, AutoBitsetTest) {
	bitset_t *bs = new_auto_bitset(8887);
	EXPECT_EQ(8887, bs->size);
	test_bitset(bs, "auto-bitset-8887");
}
