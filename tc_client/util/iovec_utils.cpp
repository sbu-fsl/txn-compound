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

#include <algorithm>
#include <vector>

#include "tc_helper.h"
#include "path_utils.h"

// We should indeed include "nfsv41.h" and use sizeof(XXX) to get the overhead
// of the operations.  But "nfsv41.h" include some libntirpc header files which
// include syntax not compatible with C++.  We could not do that, so we define
// const variable to replace the sizeof(XXX) operations.
// #include "nfsv41.h"

// # of bytes of NFSv4.1 operation code
static const size_t OPSIZE = sizeof(int);

// sizeof(PUTFH4args) == 16
static const size_t PUTFH4SZ = 16;

// sizeof(LOOKUP4args) == 16
static const size_t LOOKUP4SZ = 16;

// sizeof(OPEN4args) == 136
static const size_t OPEN4SZ = 136;

// sizeof(CLOSE4args) == 20
static const size_t CLOSE4SZ = 20;

// sizeof(COMPOUND4args) == 40
static const size_t COMPOUND4SZ = 40;

// sizeof(READ4args) == 32
static const size_t READ4SZ = 32;

// sizeof(WRITE4args) == 48
static const size_t WRITE4SZ = 48;

// Also defined in "nfsv41.h".
static const size_t NFS4_FHSIZE = 128;

// The base size of a compound (or RPC)
// 192 is the Fragment lenght of a RPC with no securiy payload (XID etc.)
// 256 is the space for securiy payload
// COMPOUND4SZ is for compound header size
static const size_t CPDSIZE = 192 + 256 + COMPOUND4SZ;

// MAX(sizeof(READ4args), sizeof(WRITE4args)) == 48;
static const size_t RDWRSIZE = 48;

// Return the RPC overhead byte excluding the data size.
static inline size_t tc_get_iov_overhead(const struct tc_iovec *iov)
{
	int n = 0;
	size_t putfh_bytes = 0;
	size_t lookup_bytes = 0;
	size_t open_close_bytes = 0;
	size_t rdwr_bytes = OPSIZE + RDWRSIZE;

	switch (iov->file.type) {
	case TC_FILE_DESCRIPTOR:
		putfh_bytes = OPSIZE + NFS4_FHSIZE;
		break;
	case TC_FILE_PATH:
		assert(iov->file.path);
		if (iov->file.path[0] == '/') {
			// PUTROOTFH does not have args
			putfh_bytes = OPSIZE;
		} else {
			putfh_bytes = PUTFH4SZ + NFS4_FHSIZE;
		}
		n = tc_path_tokenize(iov->file.path, NULL);
		// n-1 LOOKUPs.  The last component of path will be used by
		// OPEN, we count all path length here for simplicity.
		lookup_bytes =
		    strlen(iov->file.path) + (OPSIZE + LOOKUP4SZ) * (n - 1);
		// OPEN, CLOSE, and GETFH
		open_close_bytes = OPEN4SZ + CLOSE4SZ + OPSIZE * 3;
		break;
	case TC_FILE_HANDLE:
		assert(iov->file.handle);
		putfh_bytes = PUTFH4SZ + NFS4_FHSIZE;
		open_close_bytes = OPEN4SZ + CLOSE4SZ + OPSIZE * 2;
		break;
	case TC_FILE_CURRENT:
		if (iov->file.path) {
			assert(iov->file.path[0] != '/');
			n = tc_path_tokenize(iov->file.path, NULL);
			lookup_bytes = strlen(iov->file.path) +
				       (OPSIZE + LOOKUP4SZ) * (n - 1);
			open_close_bytes = OPEN4SZ + CLOSE4SZ + OPSIZE * 3;
		}
		break;
	case TC_FILE_SAVED:
		putfh_bytes = OPSIZE;  // for RESTOREFH4
		break;
	default:
		assert(false);
	}

	return putfh_bytes + lookup_bytes + open_close_bytes + rdwr_bytes;
}

struct tc_iov_array *tc_split_iov_array(const struct tc_iov_array *iova,
					int size_limit, int *nparts)
{
	std::vector<struct tc_iov_array> parts;
	std::vector<struct tc_iovec> cur_cpd; // iovec of current compound
	size_t cpd_size = CPDSIZE;

	auto add_part = [&parts, &cur_cpd, &cpd_size]() {
		struct tc_iov_array iova;
		iova.size = cur_cpd.size();
		size_t iovs_memsize = sizeof(struct tc_iovec) * iova.size;
		iova.iovs = (struct tc_iovec *)malloc(iovs_memsize);
		memmove(iova.iovs, cur_cpd.data(), iovs_memsize);
		parts.push_back(iova);
		cur_cpd.clear();
		cpd_size = CPDSIZE;
	};

	struct tc_iovec *i_iov = iova->iovs; // current iovec to split
	int i = 0;			     // index of current iovec
	size_t i_off = 0; // offset of iovs[i].data to be split

	auto add_iov_to_cpd = [&i_iov, &i_off, &cur_cpd, &cpd_size](
	    size_t len) {
		struct tc_iovec iov = *i_iov;
		iov.offset += i_off;
		iov.data += i_off;
		iov.length = len;
		iov.is_creation = i_iov->is_creation && i_off == 0;
		cur_cpd.push_back(iov);
		cpd_size += (tc_get_iov_overhead(&iov) + len);
		i_off += iov.length;
	};

	while (i < iova->size) {
		size_t space_left = size_limit - cpd_size;
		size_t data_remain =
		    tc_get_iov_overhead(i_iov) + i_iov->length - i_off;
		if (space_left >= data_remain) {
			add_iov_to_cpd(i_iov->length - i_off);
			++i;
			i_off = 0;
			i_iov = iova->iovs + i;
		} else {
			// Don't split if we will create a tiny head or tail.
			bool tiny_head = space_left <= TC_SPLIT_THRESHOLD;
			bool tiny_tail =
			    (data_remain + CPDSIZE) <= size_limit &&
			    (data_remain - space_left) <= TC_SPLIT_THRESHOLD;
			if (tiny_head || tiny_tail) {
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

