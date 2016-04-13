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
	del_buf(pbuf);
	EXPECT_EQ(0, strncmp("abcdefghijklmnopqrstu", pbuf->data, pbuf->size));
}

TEST(BufTest, AutoBuf) {
	buf_t *abuf = new_auto_buf(5);
	EXPECT_EQ(5, abuf->capacity);
	EXPECT_EQ(0, abuf->size);
	EXPECT_EQ(5, buf_append_str(abuf, "abcde"));
	EXPECT_EQ(-1, buf_append_str(abuf, "x"));
	EXPECT_EQ(5, abuf->size);
}
