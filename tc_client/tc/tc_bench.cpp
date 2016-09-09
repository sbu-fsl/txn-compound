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
#include <gflags/gflags.h>

#include "tc_api.h"
#include "tc_helper.h"

#include <string>
#include <vector>

DEFINE_bool(tc, true, "Use TC implementation");

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

static void FreePaths(vector<const char *> *paths)
{
	for (auto p : *paths)
		free((char *)p);
}

static vector<tc_iovec> NewIovecs(tc_file *files, int n, size_t offset = 0)
{
	const size_t BUFSIZE = 4096;
	vector<tc_iovec> iovs(n);
	for (int i = 0; i < n; ++i) {
		iovs[i].file = files[i];
		iovs[i].offset = offset;
		iovs[i].length = BUFSIZE;
		iovs[i].data = (char *)malloc(PATH_MAX);
		iovs[i].is_write_stable = true;
	}
	return iovs;
}

static void FreeIovecs(vector<tc_iovec> *iovs)
{
	for (auto iov : *iovs)
		free((char *)iov.data);
}

static void BM_CreateEmpty(benchmark::State &state)
{
	size_t nfiles = state.range(0);
	vector<const char *> paths = NewPaths("file-%d", nfiles);

	while (state.KeepRunning()) {
		// state.iterators()
		state.PauseTiming();
		tc_unlinkv(paths.data(), nfiles);
		state.ResumeTiming();

		tc_file *files = tc_openv_simple(paths.data(), nfiles,
						 O_CREAT | O_WRONLY, 0);
		assert(files);
		tc_res tcres = tc_closev(files, nfiles);
		assert(tc_okay(tcres));
	}

	FreePaths(&paths);
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

	FreePaths(&paths);
}
BENCHMARK(BM_OpenClose)->RangeMultiplier(2)->Range(1, 256);

static void BM_Write4K(benchmark::State &state)
{
	size_t nfiles = state.range(0);
	vector<const char *> paths = NewPaths("file-%d", nfiles);

	tc_file *files =
	    tc_openv_simple(paths.data(), nfiles, O_WRONLY | O_CREAT, 0);
	assert(files);
	vector<tc_iovec> iovs = NewIovecs(files, nfiles);

	while (state.KeepRunning()) {
		tc_res tcres = tc_writev(iovs.data(), nfiles, false);
		assert(tc_okay(tcres));
	}

	tc_closev(files, nfiles);
	FreeIovecs(&iovs);
	FreePaths(&paths);
}
BENCHMARK(BM_Write4K)->RangeMultiplier(2)->Range(1, 256);

static void BM_Append4K(benchmark::State &state)
{
	size_t nfiles = state.range(0);
	vector<const char *> paths = NewPaths("file-%d", nfiles);

	tc_file *files = tc_openv_simple(paths.data(), nfiles,
					 O_WRONLY | O_CREAT | O_APPEND, 0);
	assert(files);
	vector<tc_iovec> iovs = NewIovecs(files, nfiles, TC_OFFSET_END);

	while (state.KeepRunning()) {
		tc_res tcres = tc_writev(iovs.data(), nfiles, false);
		assert(tc_okay(tcres));
	}

	tc_closev(files, nfiles);
	FreeIovecs(&iovs);
	FreePaths(&paths);
}
BENCHMARK(BM_Append4K)->RangeMultiplier(2)->Range(1, 256);

static void BM_Read4K(benchmark::State &state)
{
	size_t nfiles = state.range(0);
	vector<const char *> paths = NewPaths("file-%d", nfiles);

	tc_file *files = tc_openv_simple(paths.data(), nfiles, O_RDONLY, 0);
	assert(files);
	vector<tc_iovec> iovs = NewIovecs(files, nfiles);

	while (state.KeepRunning()) {
		tc_res tcres = tc_readv(iovs.data(), nfiles, false);
		assert(tc_okay(tcres));
	}

	tc_closev(files, nfiles);
	FreeIovecs(&iovs);
	FreePaths(&paths);
}
BENCHMARK(BM_Read4K)->RangeMultiplier(2)->Range(1, 256);

static void BM_Read4KOpenClose(benchmark::State &state)
{
	size_t nfiles = state.range(0);
	vector<const char *> paths = NewPaths("file-%d", nfiles);
	vector<tc_file> files(nfiles);

	for (size_t i = 0; i < nfiles; ++i) {
		files[i] = tc_file_from_path(paths[i]);
	}

	vector<tc_iovec> iovs = NewIovecs(files.data(), nfiles);

	while (state.KeepRunning()) {
		tc_res tcres = tc_readv(iovs.data(), nfiles, false);
		assert(tc_okay(tcres));
	}

	FreeIovecs(&iovs);
	FreePaths(&paths);
}
BENCHMARK(BM_Read4KOpenClose)->RangeMultiplier(2)->Range(1, 256);


static void* SetUp(void)
{
	void *context;
	if (FLAGS_tc) {
		char buf[PATH_MAX];
		context = tc_init(get_tc_config_file(buf, PATH_MAX),
				  "/tmp/tc-bench-tc.log", 77);
		fprintf(stderr, "Using config file at %s\n", buf);
	} else {
		context = tc_init(NULL, "/tmp/tc-bench-posix.log", 0);
	}
	return context;
}

static void TearDown(void *context)
{
	tc_deinit(context);
}

int main(int argc, char **argv)
{
	int gbench_argc = argc;
	char **gbench_argv = argv;
	benchmark::Initialize(&gbench_argc, gbench_argv);

	int used;
	for (used = 0; used < argc; ++used) {
		if (!strstr(argv[used], "--benchmark_list_tests=") &&
		    !strstr(argv[used], "--benchmark_filter=") &&
		    !strstr(argv[used], "--benchmark_min_time=") &&
		    !strstr(argv[used], "--benchmark_repetitions=") &&
		    !strstr(argv[used],
			    "--benchmark_report_aggregates_only=") &&
		    !strstr(argv[used], "--benchmark_format=") &&
		    !strstr(argv[used], "--benchmark_out=") &&
		    !strstr(argv[used], "--benchmark_out_format=") &&
		    !strstr(argv[used], "--color_print=") &&
		    !strstr(argv[used], "--v=")) {
			break;
		}
	}

	argc -= used;
	argv += used;

	std::string usage(
	    "This program benchmark TC API with various degrees of batching.\n"
	    "Usage:    ");
	usage += argv[0];
	usage += " --tc or --notc";
	std::string gbench_flags("\n\nGoogle bench flags should come first: \n"
	    "	       [--benchmark_list_tests={true|false}]\n"
	    "          [--benchmark_filter=<regex>]\n"
	    "          [--benchmark_min_time=<min_time>]\n"
	    "          [--benchmark_repetitions=<num_repetitions>]\n"
	    "          [--benchmark_report_aggregates_only={true|false}\n"
	    "          [--benchmark_format=<console|json|csv>]\n"
	    "          [--benchmark_out=<filename>]\n"
	    "          [--benchmark_out_format=<json|console|csv>]\n"
	    "          [--color_print={true|false}]\n"
	    "          [--v=<verbosity>]\n");
	usage += gbench_flags;
	gflags::SetUsageMessage(usage);
	gflags::ParseCommandLineFlags(&argc, &argv, true);

	void *context = SetUp();
	benchmark::RunSpecifiedBenchmarks();
	TearDown(context);

	return 0;
}
