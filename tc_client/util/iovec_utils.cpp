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

#include "tc_helper.h"

const size_t SPLIT_THRESHOLD = 4096;

struct tc_iov_array *tc_split_iov_array(const struct tc_iov_array *iova,
					int size_limit, int *nparts)
{
	std::vector<struct tc_iov_array> parts;
	std::vector<struct tc_iovec> cur_cpd; // iovec of current compound
	size_t cpd_size = 0;

	auto add_part = [&parts, &cur_cpd, &cpd_size]() {
		struct tc_iov_array iova;
		iova.size = cur_cpd.size();
		size_t iovs_memsize = sizeof(struct tc_iovec) * iova.size;
		iova.iovs = (struct tc_iovec *)malloc(iovs_memsize);
		memmove(iova.iovs, cur_cpd.data(), iovs_memsize);
		parts.push_back(iova);
		cur_cpd.clear();
		cpd_size = 0;
	};

	struct tc_iovec *i_iov = iova->iovs; // current iovec to split
	int i = 0;			     // index of current iovec
	size_t i_off = 0; // offset of iovs[i].data to be split

	auto add_iov_to_cpd = [&i_iov, &i_off, &cur_cpd, &cpd_size](
	    size_t len) {
		struct tc_iovec iov = *i_iov;
		iov.offset += i_off;
		iov.length = len;
		iov.is_creation = i_iov->is_creation && i_off == 0;
		cur_cpd.push_back(iov);
		cpd_size += len;
		i_off += iov.length;
	};

	while (i < iova->size) {
		if (cpd_size + i_iov->length - i_off <= size_limit) {
			add_iov_to_cpd(i_iov->length - i_off);
			++i;
			i_off = 0;
			i_iov = iova->iovs + i;
		} else {
			if (size_limit - cpd_size <= SPLIT_THRESHOLD) {
				add_part();
				continue;
			}
			add_iov_to_cpd(size_limit - cpd_size);
			add_part();
		}
	}

	if (!cur_cpd.empty()) {
		add_part();
	}

	*nparts = parts.size();
	struct tc_iov_array *iovas =
	    (struct tc_iov_array *)malloc(sizeof(*iovas) * parts.size());
	memmove(iovas, parts.data(), sizeof(*iovas) * parts.size());
	return iovas;
}

bool tc_restore_iov_array(struct tc_iov_array *iova,
			  struct tc_iov_array **parts, int nparts)
{
	int i = 0;
	int i_off = 0;
	struct tc_iovec *i_iov = iova->iovs;
	bool res = true;

	auto advance = [&iova, &i, &i_off, &i_iov](bool eof) {
		i_iov->length = i_off;
		i_iov->is_eof = eof;
		++i;
		i_off = 0;
		i_iov = iova->iovs + i;
	};

	auto match = [&i_iov, &i_off](const struct tc_iovec *iov) {
		return tc_cmp_file(&iov->file, &i_iov->file) &&
		       iov->offset == (i_iov->offset + i_off);
	};

	for (int n = 0; n < nparts && res; ++n) {
		struct tc_iov_array *part = *parts + n;
		for (int j = 0; j < part->size; ++j) {
			struct tc_iovec *iov = part->iovs + j;
			if (!match(iov)) {
				advance(false);
			}
			if (match(iov)) {
				i_off += iov->length;
				if (iov->is_eof || i_off == i_iov->length) {
					advance(iov->is_eof);
				}
			} else {
				res = false;
				break;
			}
		}
	}
	if (i_off != 0) {
		advance(false);
	}

	if (res) {
		for (int n = 0; n < nparts; ++n) {
			free((*parts)[n].iovs);
		}
		free(*parts);
		*parts = NULL;
	}

	return res;
}

bool tc_merge_iov_array(struct tc_iov_array *iova)
{
	return false;
}

