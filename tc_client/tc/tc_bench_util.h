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

#ifndef _TC_BENCH_UTIL_H
#define _TC_BENCH_UTIL_H

#include <time.h>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "tc_api.h"

void ResetTestDirectory(const char *dir);

std::vector<const char *> NewPaths(const char *format, int n, int start = 0);

void FreePaths(std::vector<const char *> *paths);

std::vector<tc_iovec> NewIovecs(tc_file *files, int n, size_t offset = 0);

void FreeIovecs(std::vector<tc_iovec> *iovs);

std::vector<tc_attrs> NewTcAttrs(size_t nfiles, tc_attrs *values = nullptr,
			    int start = 0);

void FreeTcAttrs(std::vector<tc_attrs> *attrs);

static inline struct timespec totimespec(long sec, long nsec)
{
	struct timespec tm = {
		.tv_sec = sec,
		.tv_nsec = nsec,
	};
	return tm;
}

tc_attrs GetAttrValuesToSet(int nattrs);

void CreateFiles(std::vector<const char *>& paths);

std::vector<tc_extent_pair> NewFilePairsToCopy(size_t nfiles);

void FreeFilePairsToCopy(std::vector<tc_extent_pair> *pairs);

// dummy callback
bool DummyListDirCb(const struct tc_attrs *entry, const char *dir, void *cbarg);

// There average directory width is 17:
//
// #find linux-4.6.3/ -type d | \
//  while read dname; do ls -l $dname | wc -l; done  | \
//  awk '{s += $1} END {print s/NR;}'
// 16.8402
void CreateDirsWithContents(std::vector<const char *>& dirs);

void* SetUp(bool istc);

void TearDown(void *context);

off_t ConvertSize(const char *size_str);

// Copied from
// http://stackoverflow.com/questions/2342162/stdstring-formatting-like-sprintf
template <typename... Args>
std::string strprintf(const std::string &format, Args... args)
{
	size_t size = std::snprintf(nullptr, 0, format.c_str(), args...) +
		      1; // Extra space for '\0'
	std::unique_ptr<char[]> buf(new char[size]);
	std::snprintf(buf.get(), size, format.c_str(), args...);
	return std::string(buf.get(), buf.get() + size -
					  1); // We don't want the '\0' inside
}

off_t GetFileSize(const char *file_path);

#endif  // _TC_BENCH_UTIL_H
