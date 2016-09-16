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

#include <error.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <benchmark/benchmark.h>

#include "tc_api.h"
#include "tc_helper.h"
#include "tc_bench_util.h"

#include <string>
#include <vector>

using std::vector;
using std::string;
using namespace benchmark;

static const char *filepath;

static void ReadWriteSingle(benchmark::State &state, bool is_read)
{
	off_t filesize = GetFileSize(filepath);
	auto fn = is_read ? tc_readv : tc_writev;
	struct tc_iovec iov;
	iov.file = tc_file_from_path(filepath);
	iov.data = (char *)malloc(filesize);
	assert(iov.data);
	iov.offset = 0;
	iov.length = filesize;

	while (state.KeepRunning()) {
		tc_res tcres = fn(&iov, 1, false);
		assert(tc_okay(tcres));
	}

	free(iov.data);
}

static void BM_ReadSingle(benchmark::State &state)
{
	ReadWriteSingle(state, true);
}
BENCHMARK(BM_ReadSingle);

static void BM_WriteSingle(benchmark::State &state)
{
	ReadWriteSingle(state, false);
}
BENCHMARK(BM_WriteSingle);

int main(int argc, char **argv)
{
	benchmark::Initialize(&argc, argv);
	if (argc < 3) {
		fprintf(stderr, "usage: %s <tc|notc> filepath", argv[0]);
		exit(1);
	}
	filepath = argv[2];
	bool istc = !strcmp("tc", argv[1]);
	void *context = SetUp(istc);
	benchmark::RunSpecifiedBenchmarks();
	TearDown(context);

	return 0;
}
