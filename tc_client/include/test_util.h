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
 */

#ifndef __TC_TC_TEST_UTIL_H__
#define __TC_TC_TEST_UTIL_H__

constexpr size_t operator"" _KB(unsigned long long a) { return a << 10; }
constexpr size_t operator"" _MB(unsigned long long a) { return a << 20; }
constexpr size_t operator"" _GB(unsigned long long a) { return a << 30; }

#endif  // __TC_TC_TEST_UTIL_H__
