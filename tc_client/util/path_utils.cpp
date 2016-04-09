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

#include "util/path_utils.h"

#include <assert.h>
#include <vector>
#include <iostream>
#include "util/slice.h"

#define TC_PATH_MAX 4096

using util::Slice;

/**
 * An empty vector indicate error.
 */
static std::vector<Slice> tc_get_path_components(Slice path,
						 bool backtrace = true)
{
	assert(!path.empty());
	std::vector<Slice> components;
	bool is_absolute = path[0] == '/';
	path.trim('/');
	int beg = 0;
	int end = 0;   // component within [beg, end)
	while (end < path.size()) {
		while (end < path.size() && path[end] != '/') {
			++end;
		}
		Slice comp(path.data() + beg, end - beg);
		if (end - beg == 1) {	// two consecutive '/'
			beg = ++end;	// ignore
		} else if (comp == ".") {  // "."
			beg = ++end;	// ignore
		} else if (backtrace && comp == "..") { // ".."
			if (!components.empty()) {
				components.pop_back();
			} else if (!is_absolute) {
				// return an empty vector to indicate error
				return components;
			}
			beg = ++end;
		} else {
			components.push_back(comp);
			beg = ++end;
		}
	}

	if (components.empty()) {
		components.push_back(is_absolute ? "/" : ".");
	}

	return components;
}

int tc_path_tokenize(const char *path, slice_t *components)
{
	std::vector<Slice> comps = tc_get_path_components(path);
	if (comps.empty()) {
		return -1;
	}
	components = (slice_t *)malloc(sizeof(*components) * comps.size());
	if (!components) {
		return -1;
	}
	for (int i = 0; i < comps.size(); ++i) {
		components[i].data = comps[i].data();
		components[i].size = comps[i].size();
	}
	return comps.size();
}

int tc_path_depth(const char *path)
{
	std::vector<Slice> comps = tc_get_path_components(path);
	return comps.size();
}

int tc_path_distance(const char *src, const char *dst)
{
	std::vector<Slice> src_comps = tc_get_path_components(src);
	std::vector<Slice> dst_comps = tc_get_path_components(dst);
	int src_len = src_comps.size();
	int dst_len = src_comps.size();
	int l = 0;
	while (l < src_len && l < dst_len && src_comps[l] == dst_comps[l])
		++l;
	return src_len - l + dst_len - l;
}

static char *copy_slice(char *buf, Slice s)
{
	if (buf != s.data()) {
		memmove(buf, s.data(), s.size());
	}
	return buf + s.size();
}

static int tc_path_join_impl(char *buf, int buf_size, Slice s1, Slice s2)
{
	if (s1.empty()) {
		copy_slice(buf, s2);
		return s2.size();
	}
	if (s2.empty()) {
		copy_slice(buf, s1);
		return s1.size();
	}

	s1.rtrim('/');
	s2.ltrim('/');

	if (s1.size() + s2.size() + 1 >= buf_size)
		return -1;

	char *p = buf;
	p = copy_slice(p, s1);
	*p++ = '/';
	p = copy_slice(p, s2);

	return (p - buf);
}

int tc_path_join(const char *path1, const char *path2, char *buf, int buf_size)
{
	int len1 = strnlen(path1, TC_PATH_MAX);
	int len2 = strnlen(path2, TC_PATH_MAX);

	if (len1 >= TC_PATH_MAX || len2 >= TC_PATH_MAX)
		return -1;

	Slice p1(path1, len1);
	Slice p2(path2, len2);

	int n = tc_path_join_impl(buf, buf_size, p1, p2);
	buf[n] = 0;
	return n;
}

int tc_path_nomalize(const char *path, char *buf, size_t buf_size)
{
	int len;
	if (path == NULL || (len = strnlen(path, TC_PATH_MAX)) >= TC_PATH_MAX)
		return -1;

	std::vector<Slice> components = tc_get_path_components(path);
	if (components.empty())
		return -1;

	char *p = buf;
	int plen = 0;
	if (*path == '/') {
		*p = '/';
		++plen;
	}
	for (Slice s : components) {
		//std::cout << "comp: " << s  << ", " << s.size() << std::endl;
		plen = tc_path_join_impl(p, buf_size, Slice(p, plen), s);
		//std::cout << "path: " << path << ", " << plen << std::endl;
	}
	buf[plen] = 0;
	return plen;
}

int tc_path_rebase(const char *base, const char *path, char *buf, int buf_size)
{
	std::vector<Slice> base_comps = tc_get_path_components(base);
	std::vector<Slice> path_comps = tc_get_path_components(path);
	int l = 0;
	while (l < base_comps.size() && l < path_comps.size() &&
	       base_comps[l] == path_comps[l])
		++l;
	int dist = base_comps.size() - l + path_comps.size() - l;
	if (dist >= path_comps.size()) {
		// No need to rebase
		if (buf != path) {
			strncpy(buf, path, buf_size);
		}
		return strlen(buf);
	}

	std::vector<Slice> relative_comps;
	int result_size = 0;
	for (int i = l; i < base_comps.size(); ++i) {
		relative_comps.push_back("..");
		result_size += 2;
	}
	for (int j = l; j < path_comps.size(); ++j) {
		relative_comps.push_back(path_comps[j]);
		result_size += path_comps[j].size();
	}
	result_size += relative_comps.size() - 1;  // count "/"s
	if (result_size >= buf_size) {
		return -1;  // buffer too small
	}

	int size = 0;
	for (Slice s : relative_comps) {
		size = tc_path_join_impl(buf, buf_size, Slice(buf, size), s);
	}
	return size;
}
