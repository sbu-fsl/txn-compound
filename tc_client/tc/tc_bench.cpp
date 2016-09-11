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

#include <string>
#include <vector>

using std::vector;
using namespace benchmark;

const size_t BUFSIZE = 4096;

static void ResetTestDirectory(const char *dir)
{
	tc_rm_recursive(dir);
	tc_ensure_dir(dir, 0755, NULL);
}

static vector<const char *> NewPaths(const char *format, int n)
{
	vector<const char *> paths(n);
	for (int i = 0; i < n; ++i) {
		char *p = (char *)malloc(PATH_MAX);
		assert(p);
		snprintf(p, PATH_MAX, format, i);
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

static void ReadWrite(benchmark::State &state, int flags, bool read)
{
	size_t nfiles = state.range(0);
	vector<const char *> paths = NewPaths("file-%d", nfiles);
	auto iofunc = read ? tc_readv : tc_writev;
	size_t offset = (flags & O_APPEND) ? TC_OFFSET_END : 0;

	tc_file *files =
	    tc_openv_simple(paths.data(), nfiles, flags, 0644);
	assert(files);
	vector<tc_iovec> iovs = NewIovecs(files, nfiles, offset);

	while (state.KeepRunning()) {
		tc_res tcres = iofunc(iovs.data(), nfiles, false);
		assert(tc_okay(tcres));
	}

	tc_closev(files, nfiles);
	FreeIovecs(&iovs);
	FreePaths(&paths);
}

static void BM_Write4K(benchmark::State &state)
{
	ReadWrite(state, O_WRONLY | O_CREAT, false);
}
BENCHMARK(BM_Write4K)->RangeMultiplier(2)->Range(1, 256);

static void BM_Write4KSync(benchmark::State &state)
{
	ReadWrite(state, O_WRONLY | O_CREAT | O_SYNC, false);
}
BENCHMARK(BM_Write4KSync)->RangeMultiplier(2)->Range(1, 256);

static void BM_Append4K(benchmark::State &state)
{
	ReadWrite(state, O_WRONLY | O_CREAT | O_APPEND, false);
}
BENCHMARK(BM_Append4K)->RangeMultiplier(2)->Range(1, 256);

static void BM_Append4KSync(benchmark::State &state)
{
	ReadWrite(state, O_WRONLY | O_CREAT | O_APPEND | O_SYNC, false);
}
BENCHMARK(BM_Append4KSync)->RangeMultiplier(2)->Range(1, 256);

static void BM_Read4K(benchmark::State &state)
{
	ReadWrite(state, O_RDONLY, true);
}
BENCHMARK(BM_Read4K)->RangeMultiplier(2)->Range(1, 256);

static void BM_Read4KSync(benchmark::State &state)
{
	ReadWrite(state, O_RDONLY | O_SYNC | O_DIRECT, true);
}
BENCHMARK(BM_Read4KSync)->RangeMultiplier(2)->Range(1, 256);

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

static vector<tc_attrs> NewTcAttrs(size_t nfiles, tc_attrs *values = nullptr)
{
	vector<const char *> paths = NewPaths("file-%d", nfiles);
	vector<tc_attrs> attrs(nfiles);

	for (size_t i = 0; i < nfiles; ++i) {
		if (values) {
			attrs[i] = *values;
		} else {
			attrs[i].masks = TC_ATTRS_MASK_ALL;
		}
		attrs[i].file = tc_file_from_path(paths[i]);
	}

	return attrs;
}

static void FreeTcAttrs(vector<tc_attrs> *attrs)
{
	for (const auto& at : *attrs) {
		free((char *)at.file.path);
	}
}

static inline struct timespec totimespec(long sec, long nsec)
{
	struct timespec tm = {
		.tv_sec = sec,
		.tv_nsec = nsec,
	};
	return tm;
}

static tc_attrs GetAttrValuesToSet(int nattrs)
{
	tc_attrs attrs;

	attrs.masks = TC_ATTRS_MASK_NONE;
	if (nattrs >= 1) {
		tc_attrs_set_mode(&attrs, S_IRUSR | S_IRGRP | S_IROTH);
	}
	if (nattrs >= 2) {
		tc_attrs_set_uid(&attrs, 0);
		tc_attrs_set_gid(&attrs, 0);
	}
	if (nattrs >= 3) {
		tc_attrs_set_atime(&attrs, totimespec(time(NULL), 0));
	}
	if (nattrs >= 4) {
		tc_attrs_set_size(&attrs, 8192);
	}
	return attrs;
}

static void BM_Getattrs(benchmark::State &state)
{
	size_t nfiles = state.range(0);
	vector<tc_attrs> attrs = NewTcAttrs(nfiles);

	while (state.KeepRunning()) {
		tc_res tcres = tc_getattrsv(attrs.data(), nfiles, false);
		assert(tc_okay(tcres));
	}

	FreeTcAttrs(&attrs);
}
BENCHMARK(BM_Getattrs)->RangeMultiplier(2)->Range(1, 256);

static void BM_Setattr1(benchmark::State &state)
{
	size_t nfiles = state.range(0);
	tc_attrs values = GetAttrValuesToSet(1);
	vector<tc_attrs> attrs = NewTcAttrs(nfiles, &values);

	while (state.KeepRunning()) {
		tc_res tcres = tc_setattrsv(attrs.data(), nfiles, false);
		assert(tc_okay(tcres));
	}

	FreeTcAttrs(&attrs);
}
BENCHMARK(BM_Setattr1)->RangeMultiplier(2)->Range(1, 256);

static void BM_Setattr2(benchmark::State &state)
{
	size_t nfiles = state.range(0);
	tc_attrs values = GetAttrValuesToSet(2);
	vector<tc_attrs> attrs = NewTcAttrs(nfiles, &values);

	while (state.KeepRunning()) {
		tc_res tcres = tc_setattrsv(attrs.data(), nfiles, false);
		assert(tc_okay(tcres));
	}

	FreeTcAttrs(&attrs);
}
BENCHMARK(BM_Setattr2)->RangeMultiplier(2)->Range(1, 256);

static void BM_Setattr3(benchmark::State &state)
{
	size_t nfiles = state.range(0);
	tc_attrs values = GetAttrValuesToSet(3);
	vector<tc_attrs> attrs = NewTcAttrs(nfiles, &values);

	while (state.KeepRunning()) {
		tc_res tcres = tc_setattrsv(attrs.data(), nfiles, false);
		assert(tc_okay(tcres));
	}

	FreeTcAttrs(&attrs);
}
BENCHMARK(BM_Setattr3)->RangeMultiplier(2)->Range(1, 256);

static void BM_Setattr4(benchmark::State &state)
{
	size_t nfiles = state.range(0);
	tc_attrs values = GetAttrValuesToSet(4);
	vector<tc_attrs> attrs = NewTcAttrs(nfiles, &values);

	while (state.KeepRunning()) {
		tc_res tcres = tc_setattrsv(attrs.data(), nfiles, false);
		assert(tc_okay(tcres));
	}

	FreeTcAttrs(&attrs);
}
BENCHMARK(BM_Setattr4)->RangeMultiplier(2)->Range(1, 256);

static void CreateFiles(vector<const char *>& paths)
{
	const size_t nfiles = paths.size();
	tc_file *files =
	    tc_openv_simple(paths.data(), nfiles, O_WRONLY | O_CREAT, 0644);
	assert(files);
	vector<tc_iovec> iovs = NewIovecs(files, nfiles);
	tc_res tcres = tc_writev(iovs.data(), nfiles, false);
	assert(tc_okay(tcres));
	tc_closev(files, nfiles);
	FreeIovecs(&iovs);
}

static vector<tc_extent_pair> NewFilePairsToCopy(size_t nfiles)
{
	vector<const char *> srcs = NewPaths("file-%d", nfiles);
	CreateFiles(srcs);
	vector<const char *> dsts = NewPaths("dst-%d", nfiles);
	vector<tc_extent_pair> pairs(nfiles);
	for (size_t i = 0; i < nfiles; ++i) {
		pairs[i].src_path = srcs[i];
		pairs[i].dst_path = dsts[i];
		pairs[i].src_offset = 0;
		pairs[i].dst_offset = 0;
		pairs[i].length = BUFSIZE;
	}
	return pairs;
}

static void FreeFilePairsToCopy(vector<tc_extent_pair> *pairs)
{
	for (auto& p : *pairs) {
		free((char *)p.src_path);
		free((char *)p.dst_path);
	}
}

static void BM_Copy(benchmark::State &state)
{
	size_t nfiles = state.range(0);
	vector<tc_extent_pair> pairs = NewFilePairsToCopy(nfiles);

	while (state.KeepRunning()) {
		tc_res tcres = tc_dupv(pairs.data(), nfiles, false);
		assert(tc_okay(tcres));
	}

	FreeFilePairsToCopy(&pairs);
}
BENCHMARK(BM_Copy)->RangeMultiplier(2)->Range(1, 256);

static void BM_SSCopy(benchmark::State &state)
{
	size_t nfiles = state.range(0);
	vector<tc_extent_pair> pairs = NewFilePairsToCopy(nfiles);

	while (state.KeepRunning()) {
		tc_res tcres = tc_copyv(pairs.data(), nfiles, false);
		assert(tc_okay(tcres));
	}

	FreeFilePairsToCopy(&pairs);
}
BENCHMARK(BM_SSCopy)->RangeMultiplier(2)->Range(1, 256);

static void BM_Mkdir(benchmark::State &state)
{
	size_t ndirs = state.range(0);
	vector<const char *> paths = NewPaths("Bench-Mkdir/dir-%d", ndirs);
	vector<tc_attrs> dirs(ndirs);

	while (state.KeepRunning()) {
		state.PauseTiming();
		ResetTestDirectory("Bench-Mkdir");
		for (size_t i = 0; i < ndirs; ++i) {
			tc_set_up_creation(&dirs[i], paths[i], 0755);
		}
		state.ResumeTiming();

		tc_res tcres = tc_mkdirv(dirs.data(), ndirs, false);
		assert(tc_okay(tcres));

	}

	FreePaths(&paths);
}
BENCHMARK(BM_Mkdir)->RangeMultiplier(2)->Range(1, 256);

static void BM_Symlink(benchmark::State &state)
{
	size_t nfiles = state.range(0);
	vector<const char *> files = NewPaths("Bench-Symlink/file-%d", nfiles);
	vector<const char *> links = NewPaths("Bench-Symlink/link-%d", nfiles);

	ResetTestDirectory("Bench-Symlink");
	CreateFiles(files);
	while (state.KeepRunning()) {
		tc_res tcres =
		    tc_symlinkv(files.data(), links.data(), nfiles, false);
		assert(tc_okay(tcres));

		state.PauseTiming();
		tc_unlinkv(links.data(), nfiles);
		state.ResumeTiming();
	}

	FreePaths(&files);
	FreePaths(&links);
}
BENCHMARK(BM_Symlink)->RangeMultiplier(2)->Range(1, 256);

static void BM_Readlink(benchmark::State &state)
{
	size_t nfiles = state.range(0);
	vector<const char *> files = NewPaths("Bench-Readlink/file-%d", nfiles);
	vector<const char *> links = NewPaths("Bench-Readlink/link-%d", nfiles);
	vector<char *> bufs(nfiles);
	vector<size_t> buf_sizes(nfiles, PATH_MAX);

	for (size_t i = 0; i < nfiles; ++i) {
		bufs[i] = (char *)malloc(PATH_MAX);
	}

	ResetTestDirectory("Bench-Readlink");
	CreateFiles(files);
	tc_symlinkv(files.data(), links.data(), nfiles, false);
	while (state.KeepRunning()) {
		tc_res tcres = tc_readlinkv(links.data(), bufs.data(),
					    buf_sizes.data(), nfiles, false);
		assert(tc_okay(tcres));
	}

	for (size_t i = 0; i < nfiles; ++i) {
		free(bufs[i]);
	}
	FreePaths(&files);
	FreePaths(&links);
}
BENCHMARK(BM_Readlink)->RangeMultiplier(2)->Range(1, 256);

static void BM_Rename(benchmark::State &state)
{
	size_t nfiles = state.range(0);
	vector<const char *> srcs = NewPaths("Bench-Rename/src-%d", nfiles);
	vector<const char *> dsts = NewPaths("Bench-Rename/dst-%d", nfiles);
	vector<tc_file_pair> pairs(nfiles);

	for (size_t i = 0; i < nfiles; ++i) {
		pairs[i].src_file = tc_file_from_path(srcs[i]);
		pairs[i].dst_file = tc_file_from_path(dsts[i]);
	}

	ResetTestDirectory("Bench-Rename");
	CreateFiles(srcs);
	while (state.KeepRunning()) {
		tc_res tcres = tc_renamev(pairs.data(), nfiles, false);
		assert(tc_okay(tcres));

		// switch srcs and dsts
		state.PauseTiming();
		for (size_t i = 0; i < nfiles; ++i) {
			std::swap(pairs[i].src_file, pairs[i].dst_file);
		}
		state.ResumeTiming();
	}

	FreePaths(&srcs);
	FreePaths(&dsts);
}
BENCHMARK(BM_Rename)->RangeMultiplier(2)->Range(1, 256);

static void BM_Remove(benchmark::State &state)
{
	size_t nfiles = state.range(0);
	vector<const char *> paths = NewPaths("Bench-Removev/file-%d", nfiles);

	ResetTestDirectory("Bench-Removev");
	while (state.KeepRunning()) {
		state.PauseTiming();
		CreateFiles(paths);
		state.ResumeTiming();

		tc_res tcres = tc_unlinkv(paths.data(), nfiles);
		assert(tc_okay(tcres));
	}

	FreePaths(&paths);
}
BENCHMARK(BM_Remove)->RangeMultiplier(2)->Range(1, 256);

// dummy callback
static bool DummyListDirCb(const struct tc_attrs *entry, const char *dir,
			   void *cbarg)
{
	return true;
}

// There average directory width is 17:
//
// #find linux-4.6.3/ -type d | \
//  while read dname; do ls -l $dname | wc -l; done  | \
//  awk '{s += $1} END {print s/NR;}'
// 16.8402
static void CreateDirsWithContents(vector<const char *>& dirs)
{
	const int kFilesPerDir = 17;
	vector<tc_attrs> attrs(dirs.size());
	for (size_t i = 0; i < dirs.size(); ++i) {
		tc_set_up_creation(&attrs[i], dirs[i], 0755);
	}
	tc_res tcres = tc_mkdirv(attrs.data(), dirs.size(), false);
	assert(tc_okay(tcres));

	for (size_t i = 0; i < dirs.size(); ++i) {
		char p[PATH_MAX];
		snprintf(p, PATH_MAX, "%s/%%d", dirs[i]);
		auto files = NewPaths(p, 17);
		CreateFiles(files);
		FreePaths(&files);
	}
}

static void BM_Listdir(benchmark::State &state)
{
	size_t nfiles = state.range(0);
	vector<const char *> dirs = NewPaths("Bench-Listdir/dir-%d", nfiles);

	ResetTestDirectory("Bench-Listdir");
	CreateDirsWithContents(dirs);

	while (state.KeepRunning()) {
		tc_res tcres =
		    tc_listdirv(dirs.data(), nfiles, TC_ATTRS_MASK_ALL, 0,
				false, DummyListDirCb, NULL, false);
		assert(tc_okay(tcres));
	}

	FreePaths(&dirs);
}
BENCHMARK(BM_Listdir)->RangeMultiplier(2)->Range(1, 256);


static void* SetUp(bool istc)
{
	void *context;
	if (istc) {
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
	benchmark::Initialize(&argc, argv);
	bool istc = argc > 1 && !strcmp("tc", argv[1]);
	void *context = SetUp(istc);
	benchmark::RunSpecifiedBenchmarks();
	TearDown(context);

	return 0;
}
