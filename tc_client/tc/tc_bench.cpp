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

#include "benchmark/benchmark.h"
#include "tc_api.h"
#include "tc_helper.h"

#include <string>
#include <vector>

using std::vector;
using namespace benchmark;

static vector<const char *> NewPaths(const char *format, int n)
{
	vector<const char *> paths(n);
	for (int i = 0; i < n; ++i) {
		char *p = (char *)malloc(PATH_MAX);
		assert(p);
		snprintf(p, PATH_MAX, format, n);
		paths[i] = p;
	}
	return paths;
}

static void DeletePaths(vector<const char *> *paths)
{
	for (auto p : *paths)
		free((char *)p);
}

static void BM_CreateEmpty(benchmark::State &state)
{
	size_t nfiles = state.range(0);
	vector<const char *> paths = NewPaths("file-%d", nfiles);

	while (state.KeepRunning()) {
		// state.iterators()
		tc_file *files = tc_openv_simple(paths.data(), nfiles,
						 O_CREAT | O_WRONLY, 0);
		assert(files);
		tc_res tcres = tc_closev(files, nfiles);
		assert(tc_okay(tcres));
	}

	DeletePaths(&paths);
}
BENCHMARK(BM_CreateEmpty)->RangeMultiplier(2)->Range(1, 256);

static void BM_OpenClose(benchmark::State &state)
{
	size_t nfiles = state.range(0);
	vector<const char *> paths = NewPaths("file-%d", nfiles);

	while (state.KeepRunning()) {
		tc_file *files =
		    tc_openv_simple(paths.data(), nfiles, O_RDONLY, 0);
		assert(files);
		tc_res tcres = tc_closev(files, nfiles);
		assert(tc_okay(tcres));
	}

	DeletePaths(&paths);
}
BENCHMARK(BM_OpenClose)->RangeMultiplier(2)->Range(1, 256);

BENCHMARK_MAIN();
