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

/**
 * XXX: To add a new test, don't forget to register the test in
 * REGISTER_TYPED_TEST_CASE_P().
 *
 * This file uses an advanced GTEST feature called Type-Parameterized Test,
 * which is documented at
 * https://github.com/google/googletest/blob/master/googletest/docs/V1_7_AdvancedGuide.md
 */
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>

#include <algorithm>
#include <list>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "tc_api.h"
#include "tc_helper.h"
#include "path_utils.h"
#include "test_util.h"
#include "util/fileutil.h"
#include "path_utils.h"
#include "log.h"

#define TCTEST_ERR(fmt, args...) LogCrit(COMPONENT_TC_TEST, fmt, ##args)
#define TCTEST_WARN(fmt, args...) LogWarn(COMPONENT_TC_TEST, fmt, ##args)
#define TCTEST_INFO(fmt, args...) LogInfo(COMPONENT_TC_TEST, fmt, ##args)
#define TCTEST_DEBUG(fmt, args...) LogDebug(COMPONENT_TC_TEST, fmt, ##args)

#define EXPECT_OK(x)                                                           \
	EXPECT_TRUE(tc_okay(x)) << "Failed at " << x.index << ": "             \
				<< strerror(x.err_no)
#define EXPECT_NOTNULL(x) EXPECT_TRUE(x != NULL) << #x << " is NULL"

#define new_auto_path(fmt, args...)                                            \
	tc_format_path((char *)alloca(PATH_MAX), fmt, ##args)

namespace
{
void DoParallel(int nthread, std::function<void(int)> worker)
{
	std::list<std::thread> threads;
	for (int i = 0; i < nthread; ++i) {
		threads.emplace_back(worker, i);
	}
	for (auto it = threads.begin(); it != threads.end(); ++it) {
		it->join();
	}
}
} // anonymous namespace

/**
 * Ensure files or directories do not exist before test.
 */
bool Removev(const char **paths, int count) {
	return tc_okay(tc_unlinkv(paths, count));
}

/**
 * Set the TC I/O vector
 */
static tc_iovec *build_iovec(tc_file *files, int count, int offset)
{
	int i = 0, N = 4096;
	tc_iovec *iov = NULL;

	iov = (tc_iovec *)calloc(count, sizeof(tc_iovec));

	while (i < count) {
		tc_iov2file(&iov[i], &files[i], offset, N, (char *)malloc(N));
		i++;
	}

	return iov;
}

static char *getRandomBytes(int N);

static void tc_touchv(const char **paths, int count, int filesize)
{
	tc_iovec *iovs;
	char *buf;

	iovs = (tc_iovec *)alloca(count * sizeof(*iovs));
	buf = filesize ? getRandomBytes(filesize) : NULL;

	for (int i = 0; i < count; ++i) {
		tc_iov4creation(&iovs[i], paths[i], filesize, buf);
	}

	EXPECT_OK(tc_writev(iovs, count, false));

	if (buf) {
		free(buf);
	}
}

static inline void tc_touch(const char *path, int size)
{
	tc_touchv(&path, 1, size);
}

static inline char *tc_format_path(char *path, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vsnprintf(path, PATH_MAX, format, args);
	va_end(args);

	return path;
}

static inline void tc_ensure_parent_dir(const char *path)
{
	char dirpath[PATH_MAX];
	slice_t dir = tc_path_dirname(path);
	strncpy(dirpath, dir.data, dir.size);
	dirpath[dir.size] = '\0';
	tc_ensure_dir(dirpath, 0755, NULL);
}

class TcPosixImpl {
public:
	static void *tcdata;
	static constexpr const char* POSIX_TEST_DIR = "/tmp/tc_posix_test";
	static void SetUpTestCase() {
		tcdata = tc_init(NULL, "/tmp/tc-posix.log", 0);
		TCTEST_WARN("Global SetUp of Posix Impl\n");
		util::CreateOrUseDir(POSIX_TEST_DIR);
		chdir(POSIX_TEST_DIR);
	}
	static void TearDownTestCase() {
		TCTEST_WARN("Global TearDown of Posix Impl\n");
		tc_deinit(tcdata);
		//sleep(120);
	}
	static void SetUp() {
		TCTEST_WARN("SetUp Posix Impl Test\n");
	}
	static void TearDown() {
		TCTEST_WARN("TearDown Posix Impl Test\n");
	}
};
void *TcPosixImpl::tcdata = NULL;

class TcNFS4Impl {
public:
	static void *tcdata;
	static void SetUpTestCase() {
		tcdata = tc_init(
		    get_tc_config_file((char *)alloca(PATH_MAX), PATH_MAX),
		    "/tmp/tc-nfs4.log", 77);
		TCTEST_WARN("Global SetUp of NFS4 Impl\n");
		/* TODO: recreate test dir if exist */
		EXPECT_OK(tc_ensure_dir("/vfs0/tc_nfs4_test", 0755, NULL));
		tc_chdir("/vfs0/tc_nfs4_test");  /* change to mnt point */
	}
	static void TearDownTestCase() {
		TCTEST_WARN("Global TearDown of NFS4 Impl\n");
		tc_deinit(tcdata);
	}
	static void SetUp() {
		TCTEST_WARN("SetUp NFS4 Impl Test\n");
	}
	static void TearDown() {
		TCTEST_WARN("TearDown NFS4 Impl Test\n");
	}
};
void *TcNFS4Impl::tcdata = NULL;

template <typename T>
class TcTest : public ::testing::Test {
public:
	static void SetUpTestCase() {
		T::SetUpTestCase();
	}
	static void TearDownTestCase() {
		T::TearDownTestCase();
	}
	void SetUp() override {
		T::SetUp();
	}
	void TearDown() override {
		T::TearDown();
	}
};

TYPED_TEST_CASE_P(TcTest);

/**
 * TC-Read and Write test using
 * File path
 */
TYPED_TEST_P(TcTest, WritevCanCreateFiles)
{
	const char *PATHS[] = { "WritevCanCreateFiles1.txt",
				"WritevCanCreateFiles2.txt",
				"WritevCanCreateFiles3.txt",
				"WritevCanCreateFiles4.txt" };
	const int count = sizeof(PATHS)/sizeof(PATHS[0]);

	Removev(PATHS, count);

	tc_iovec *writev = (tc_iovec *)malloc(sizeof(tc_iovec) * count);
	for (int i = 0; i < count; ++i) {
		tc_iov4creation(&writev[i], PATHS[i], 4096,
				getRandomBytes(4096));
	}

	EXPECT_OK(tc_writev(writev, count, false));

	tc_iovec *readv = (tc_iovec *)malloc(sizeof(tc_iovec) * count);
	for (int i = 0; i < count; ++i) {
		tc_iov2path(&readv[i], PATHS[i], 0, 4096,
			    (char *)malloc(4096));
	}

	EXPECT_OK(tc_readv(readv, count, false));

	EXPECT_TRUE(compare_content(writev, readv, count));

	free_iovec(writev, count);
	free_iovec(readv, count);
}

/**
 * TC-Read and Write test using
 * File Descriptor
 */
TYPED_TEST_P(TcTest, TestFileDesc)
{
	const int N = 4;
	const char *PATHS[] = { "TcTest-TestFileDesc1.txt",
				"TcTest-TestFileDesc2.txt",
				"TcTest-TestFileDesc3.txt",
				"TcTest-TestFileDesc4.txt" };
	char data[] = "abcd123";
	tc_res res;
	int i = 0;
	tc_file *files;

	Removev(PATHS, 4);

	files = tc_openv_simple(PATHS, N, O_RDWR | O_CREAT, 0);
	EXPECT_NOTNULL(files);

	struct tc_iovec *writev = NULL;
	writev = build_iovec(files, N, 0);
	EXPECT_FALSE(writev == NULL);

	EXPECT_OK(tc_writev(writev, N, false));

	struct tc_iovec *readv = NULL;
	readv = build_iovec(files, N, 0);
	EXPECT_FALSE(readv == NULL);

	EXPECT_OK(tc_readv(readv, N, false));

	EXPECT_TRUE(compare_content(writev, readv, N));

	tc_closev(files, N);
	free_iovec(writev, N);
	free_iovec(readv, N);
}

/**
 * Compare the attributes once set, to check if set properly
 */

bool compare_attrs(tc_attrs *attrs1, tc_attrs *attrs2, int count)
{
	int i = 0;
	tc_attrs *a = NULL;
	tc_attrs *b = NULL;

	for (i = 0; i < count; ++i) {
		a = attrs1 + i;
		b = attrs2 + i;
		if (a->masks.has_mode != b->masks.has_mode)
			return false;
		if (a->masks.has_mode &&
		    (a->mode & (S_IRWXU | S_IRWXG | S_IRWXO)) !=
		    (b->mode & (S_IRWXU | S_IRWXG | S_IRWXO))) {
			TCTEST_WARN("Mode does not match: %x vs %x\n",
				    a->mode, b->mode);
			TCTEST_WARN("TYPE BITS: %x vs %x\n", (a->mode & S_IFMT),
				    (b->mode & S_IFMT));
			TCTEST_WARN("OWNER BITS: %x vs %x\n",
				    (a->mode & S_IRWXU), (b->mode & S_IRWXU));
			TCTEST_WARN("GROUP BITS: %x vs %x\n",
				    (a->mode & S_IRWXO), (b->mode & S_IRWXO));
			return false;
		}

		if (a->masks.has_rdev != b->masks.has_rdev)
			return false;
		if (a->masks.has_rdev && a->rdev != b->rdev) {
			TCTEST_WARN("rdev does not match\n");
			TCTEST_WARN(" %d %d\n", a->rdev, b->rdev);
			return false;
		}

		if (a->masks.has_nlink != b->masks.has_nlink)
			return false;
		if (a->masks.has_nlink && a->nlink != b->nlink) {
			TCTEST_WARN("nlink does not match\n");
			TCTEST_WARN(" %d %d\n", a->nlink, b->nlink);
			return false;
		}

		if (a->masks.has_uid != b->masks.has_uid)
			return false;
		if (a->masks.has_uid && a->uid != b->uid) {
			TCTEST_WARN("uid does not match\n");
			TCTEST_WARN(" %d %d\n", a->uid, b->uid);
			return false;
		}

		if (a->masks.has_gid != b->masks.has_gid)
			return false;
		if (a->masks.has_gid && a->gid != b->gid) {
			TCTEST_WARN("gid does not match\n");
			TCTEST_WARN(" %d %d\n", a->gid, b->gid);
			return false;
		}

		if (a->masks.has_ctime != b->masks.has_ctime)
			return false;
		if (a->masks.has_ctime &&
		    memcmp((void *)&(a->ctime), (void *)&(b->ctime),
			   sizeof(b->ctime))) {
			TCTEST_WARN("ctime does not match\n");
			TCTEST_WARN(" %d %d\n", a->ctime,
				   b->ctime);
			return false;
		}

		if (a->masks.has_mtime != b->masks.has_mtime)
			return false;
		if (a->masks.has_mtime &&
		    memcmp((void *)&(a->mtime), (void *)&(b->mtime),
			   sizeof(b->mtime))) {
			TCTEST_WARN("mtime does not match\n");
			TCTEST_WARN(" %d %d\n", a->mtime, b->mtime);
			return false;
		}
	}

	return true;
}

static inline struct timespec totimespec(long sec, long nsec)
{
	struct timespec tm = {
		.tv_sec = sec,
		.tv_nsec = nsec,
	};
	return tm;
}

/**
 * Set the TC test Attributes
 */
static tc_attrs *set_tc_attrs(struct tc_attrs *attrs, int count)
{
	int i = 0;
	uid_t uid[] = { 2711, 456, 789 };
	gid_t gid[] = { 87, 4566, 2311 };
	mode_t mode[] = { S_IRUSR | S_IRGRP | S_IROTH,
			  S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH, S_IRWXU };
	size_t size[] = { 256, 56, 125 };
	time_t atime[] = { time(NULL), 1234, 567 };

	if (count > 3) {
		TCTEST_WARN("count should be less than 4\n");
		return NULL;
	}

	for (i = 0; i < count; ++i) {
		tc_attrs_set_mode(attrs + i, mode[i]);
		tc_attrs_set_size(attrs + i, size[i]);
		tc_attrs_set_uid(attrs + i, uid[i]);
		tc_attrs_set_gid(attrs + i, gid[i]);
		tc_attrs_set_atime(attrs + i, totimespec(atime[i], 0));
		tc_attrs_set_atime(attrs + i, totimespec(time(NULL), 0));
	}

	return attrs;
}

/* Set the TC attributes masks */
static void set_attr_masks(tc_attrs *write, tc_attrs *read, int count)
{
	int i = 0;
	for (i = 0; i < count; ++i) {
		read[i].file = write[i].file;
		read[i].masks = write[i].masks;
	}
}

/**
 * TC-Set/Get Attributes test
 * using File Path
 */
TYPED_TEST_P(TcTest, AttrsTestPath)
{
	const char *PATH[] = { "WritevCanCreateFiles1.txt",
			       "WritevCanCreateFiles2.txt",
			       "WritevCanCreateFiles3.txt" };
	tc_res res = { 0 };
	int i;
	const int count = 3;
	struct tc_attrs *attrs1 = (tc_attrs *)calloc(count, sizeof(tc_attrs));
	struct tc_attrs *attrs2 = (tc_attrs *)calloc(count, sizeof(tc_attrs));

	EXPECT_NOTNULL(attrs1);
	EXPECT_NOTNULL(attrs2);

	for (i = 0; i < count; ++i) {
		attrs1[i].file = tc_file_from_path(PATH[i]);
		attrs2[i].file = attrs1[i].file;
	}

	attrs1 = set_tc_attrs(attrs1, count);
	EXPECT_OK(tc_setattrsv(attrs1, count, false));

	for (i = 0; i < count; ++i) {
		attrs2[i].masks = attrs1[i].masks;
	}
	EXPECT_OK(tc_getattrsv(attrs2, count, false));

	EXPECT_TRUE(compare_attrs(attrs1, attrs2, count));

	free(attrs1);
	free(attrs2);
}

/**
 * TC-Set/Get Attributes test
 * with symlinks
 */
TYPED_TEST_P(TcTest, AttrsTestSymlinks)
{
	const char *PATHS[] = { "AttrsTestSymlinks-Linked1.txt",
				"AttrsTestSymlinks-Linked2.txt",
				"AttrsTestSymlinks-Linked3.txt" };
	const char *LPATHS[] = { "AttrsTestSymlinks-Link1.txt",
				 "AttrsTestSymlinks-Link2.txt",
				 "AttrsTestSymlinks-Link3.txt" };
	tc_res res = { 0 };
	struct tc_iovec iov;
	int i;
	const int count = 3;
	struct tc_attrs *attrs1 = (tc_attrs *)calloc(count, sizeof(tc_attrs));
	struct tc_attrs *attrs2 = (tc_attrs *)calloc(count, sizeof(tc_attrs));

	EXPECT_NOTNULL(attrs1);
	EXPECT_NOTNULL(attrs2);

	Removev(PATHS, count);
	Removev(LPATHS, count);

	EXPECT_OK(tc_symlinkv(PATHS, LPATHS, count, false));

	for (i = 0; i < count; ++i) {
		tc_iov4creation(&iov, PATHS[i], 100, getRandomBytes(100));
		EXPECT_NOTNULL(iov.data);
		EXPECT_OK(tc_writev(&iov, 1, false));

		attrs1[i].file = tc_file_from_path(LPATHS[i]);
		tc_attrs_set_mode(&attrs1[i], S_IRUSR);
		tc_attrs_set_atime(&attrs1[i], totimespec(time(NULL), 0));
		attrs2[i] = attrs1[i];
	}

	EXPECT_OK(tc_setattrsv(attrs1, count, false));
	EXPECT_OK(tc_getattrsv(attrs2, count, false));
	EXPECT_TRUE(compare_attrs(attrs1, attrs2, count));

	tc_attrs_set_mode(&attrs1[0], S_IRUSR | S_IRGRP);
	EXPECT_OK(tc_setattrsv(attrs1, count, false));
	EXPECT_OK(tc_lgetattrsv(attrs2, count, false));

	EXPECT_FALSE(S_IROTH & attrs1[0].mode);
	EXPECT_TRUE(S_IROTH & attrs2[0].mode);
	EXPECT_FALSE(compare_attrs(attrs1, attrs2, count));

	EXPECT_OK(tc_getattrsv(attrs2, count, false));
	EXPECT_TRUE(compare_attrs(attrs1, attrs2, count));

	free(attrs1);
	free(attrs2);
}

/*
 * TC-Set/Get Attributes test
 * using File Descriptor
 */
TYPED_TEST_P(TcTest, AttrsTestFileDesc)
{
	const char *PATH[] = { "WritevCanCreateFiles4.txt",
			       "WritevCanCreateFiles5.txt",
			       "WritevCanCreateFiles6.txt" };
	int i = 0;
	const int count = 3;
	tc_file *tcfs;
	struct tc_attrs *attrs1 = (tc_attrs *)calloc(count, sizeof(tc_attrs));
	struct tc_attrs *attrs2 = (tc_attrs *)calloc(count, sizeof(tc_attrs));

	EXPECT_NOTNULL(attrs1);
	EXPECT_NOTNULL(attrs2);

	Removev(PATH, count);
	tcfs = tc_openv_simple(PATH, count, O_RDWR | O_CREAT, 0);
	EXPECT_NOTNULL(tcfs);

	for (int i = 0; i < count; ++i) {
		attrs2[i].file = attrs1[i].file = tcfs[i];
	}

	set_tc_attrs(attrs1, count);
	EXPECT_OK(tc_setattrsv(attrs1, count, false));

	for (i = 0; i < count; ++i) {
		attrs2[i].masks = attrs1[i].masks;
	}
	EXPECT_OK(tc_getattrsv(attrs2, count, false));

	EXPECT_TRUE(compare_attrs(attrs1, attrs2, count));

	tc_closev(tcfs, count);

	free(attrs1);
	free(attrs2);
}

static int tc_cmp_attrs_by_name(const void *a, const void *b)
{
	const tc_attrs *attrs1 = (const tc_attrs *)a;
	const tc_attrs *attrs2 = (const tc_attrs *)b;
	return strcmp(attrs1->file.path, attrs2->file.path);
}

/**
 * List Directory Contents Test
 */
TYPED_TEST_P(TcTest, ListDirContents)
{
	const char *DIR_PATH = "TcTest-ListDir";
	tc_attrs *contents;
	int count = 0;

	EXPECT_OK(tc_ensure_dir(DIR_PATH, 0755, 0));
	tc_touch("TcTest-ListDir/file1.txt", 1);
	tc_touch("TcTest-ListDir/file2.txt", 2);
	tc_touch("TcTest-ListDir/file3.txt", 3);

	EXPECT_OK(tc_listdir(DIR_PATH, TC_ATTRS_MASK_ALL, 3, false, &contents,
			     &count));
	EXPECT_EQ(3, count);
	qsort(contents, count, sizeof(*contents), tc_cmp_attrs_by_name);

	tc_attrs *read_attrs = (tc_attrs *)calloc(count, sizeof(tc_attrs));
	read_attrs[0].file = tc_file_from_path("TcTest-ListDir/file1.txt");
	read_attrs[1].file = tc_file_from_path("TcTest-ListDir/file2.txt");
	read_attrs[2].file = tc_file_from_path("TcTest-ListDir/file3.txt");
	read_attrs[0].masks = read_attrs[1].masks = read_attrs[2].masks =
	    TC_ATTRS_MASK_ALL;
	EXPECT_OK(tc_getattrsv(read_attrs, count, false));

	EXPECT_TRUE(compare_attrs(contents, read_attrs, count));

	tc_free_attrs(contents, count, true);
	free(read_attrs);
}

TYPED_TEST_P(TcTest, ListLargeDir)
{
	EXPECT_OK(tc_ensure_dir("TcTest-ListLargeDir", 0755, 0));
	buf_t *name = new_auto_buf(PATH_MAX);
	const int N = 512;
	for (int i = 1; i <= N; ++i) {
		buf_printf(name, "TcTest-ListLargeDir/large-file%05d", i);
		tc_touch(asstr(name), i);
	}

	tc_attrs *contents;
	int count = 0;
	EXPECT_OK(tc_listdir("TcTest-ListLargeDir", TC_ATTRS_MASK_ALL, 0,
			     false, &contents, &count));
	EXPECT_EQ(N, count);
	qsort(contents, count, sizeof(*contents), tc_cmp_attrs_by_name);
	for (int i = 1; i <= N; ++i) {
		buf_printf(name, "TcTest-ListLargeDir/large-file%05d", i);
		EXPECT_STREQ(asstr(name), contents[i - 1].file.path);
	}
	tc_free_attrs(contents, count, true);
}

TYPED_TEST_P(TcTest, ListDirRecursively)
{
	EXPECT_OK(tc_ensure_dir("TcTest-ListDirRecursively/00/00", 0755, 0));
	EXPECT_OK(tc_ensure_dir("TcTest-ListDirRecursively/00/01", 0755, 0));
	EXPECT_OK(tc_ensure_dir("TcTest-ListDirRecursively/01", 0755, 0));

	tc_touch("TcTest-ListDirRecursively/00/00/1.txt", 0);
	tc_touch("TcTest-ListDirRecursively/00/00/2.txt", 0);
	tc_touch("TcTest-ListDirRecursively/00/01/3.txt", 0);
	tc_touch("TcTest-ListDirRecursively/00/01/4.txt", 0);
	tc_touch("TcTest-ListDirRecursively/01/5.txt", 0);

	tc_attrs *contents;
	int count = 0;
	EXPECT_OK(tc_listdir("TcTest-ListDirRecursively", TC_ATTRS_MASK_ALL, 0,
			     true, &contents, &count));
	qsort(contents, count, sizeof(*contents), tc_cmp_attrs_by_name);
	const char *expected[] = {
		"TcTest-ListDirRecursively/00",
		"TcTest-ListDirRecursively/00/00",
		"TcTest-ListDirRecursively/00/00/1.txt",
		"TcTest-ListDirRecursively/00/00/2.txt",
		"TcTest-ListDirRecursively/00/01",
		"TcTest-ListDirRecursively/00/01/3.txt",
		"TcTest-ListDirRecursively/00/01/4.txt",
		"TcTest-ListDirRecursively/01",
		"TcTest-ListDirRecursively/01/5.txt",
	};
	EXPECT_EQ(count, sizeof(expected) / sizeof(expected[0]));
	for (int i = 0; i < count; ++i) {
		EXPECT_STREQ(expected[i], contents[i].file.path);
	}
	tc_free_attrs(contents, count, true);
}

/**
 * Rename File Test
 */
TYPED_TEST_P(TcTest, RenameFile)
{
	int i = 0;
	const char *src_path[] = { "WritevCanCreateFiles1.txt",
				   "WritevCanCreateFiles2.txt",
				   "WritevCanCreateFiles3.txt",
				   "WritevCanCreateFiles4.txt" };

	const char *dest_path[] = { "rename1.txt", "rename2.txt",
				    "rename3.txt", "rename4.txt" };

	tc_file_pair *files = (tc_file_pair *)calloc(4, sizeof(tc_file_pair));

	for (i = 0; i < 4; ++i) {
		files[i].src_file = tc_file_from_path(src_path[i]);
		files[i].dst_file = tc_file_from_path(dest_path[i]);
	}

	EXPECT_OK(tc_renamev(files, 4, false));

	/* TODO use listdir to check src files no longer exist */

	free(files);
}

/**
 * Remove File Test
 */
TYPED_TEST_P(TcTest, RemoveFileTest)
{
	const char *path[] = { "rename1.txt", "rename2.txt",
			       "rename3.txt", "rename4.txt" };

	tc_file *file = (tc_file *)calloc(4, sizeof(tc_file));

	for (int i = 0; i < 4; ++i) {
		file[i] = tc_file_from_path(path[i]);
	}

	EXPECT_OK(tc_removev(file, 4, false));

	free(file);
}

TYPED_TEST_P(TcTest, MakeDirectories)
{
	mode_t mode[] = { S_IRWXU, S_IRUSR | S_IRGRP | S_IROTH,
			  S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH };
	const char *path[] = { "a", "b", "c" };
	struct tc_attrs dirs[3];

	Removev(path, 3);

	for (int i = 0; i < 3; ++i) {
		tc_set_up_creation(&dirs[i], path[i], 0755);
	}

	EXPECT_OK(tc_mkdirv(dirs, 3, false));
}

TYPED_TEST_P(TcTest, MakeManyDirsDontFitInOneCompound)
{
	const int NDIRS = 64;
	std::vector<tc_attrs> dirs;
	EXPECT_TRUE(tc_rm_recursive("ManyDirs"));
	char buf[PATH_MAX];
	std::vector<std::string> paths;

	for (int i = 0; i < NDIRS; ++i) {
		snprintf(buf, PATH_MAX, "ManyDirs/a%d/b/c/d/e/f/g/h", i);
		std::string p(buf);
		int n = p.length();
		while (n != std::string::npos) {
			paths.emplace_back(p.data(), n);
			n = p.find_last_of('/', n - 1);
		}
	}

	std::sort(paths.begin(), paths.end());
	auto end = std::unique(paths.begin(), paths.end());
	for (auto it = paths.begin(); it != end; ++it) {
		tc_attrs tca;
		tc_set_up_creation(&tca, it->c_str(), 0755);
		dirs.push_back(tca);
	}

	EXPECT_OK(tc_mkdirv(dirs.data(), dirs.size(), false));
}

/**
 * Append test case
 */
TYPED_TEST_P(TcTest, Append)
{
	const char *PATH = "TcTest-Append.txt";
	int i = 0;
	const int N = 4096;
	struct stat st;
	char *data;
	char *data_read;
	struct tc_iovec iov;

	Removev(&PATH, 1);

	data = (char *)getRandomBytes(3 * N);
	data_read = (char *)malloc(3 * N);
	EXPECT_NOTNULL(data);
	EXPECT_NOTNULL(data_read);

	tc_iov4creation(&iov, PATH, N, data);

	EXPECT_OK(tc_writev(&iov, 1, false));

	for (i = 0; i < 2; ++i) {
		iov.offset = TC_OFFSET_END;
		iov.data = data + N * (i + 1);
		iov.is_creation = false;
		EXPECT_OK(tc_writev(&iov, 1, false));
	}

	iov.offset = 0;
	iov.length = 3 * N;
	iov.data = data_read;
	EXPECT_OK(tc_readv(&iov, 1, false));
	EXPECT_TRUE(iov.is_eof);
	EXPECT_EQ(3 * N, iov.length);
	EXPECT_EQ(0, memcmp(data, data_read, 3 * N));

	free(data);
	free(data_read);
}

TYPED_TEST_P(TcTest, SuccessiveReads)
{
	const char *path = "TcTest-SuccesiveReads.txt";
	struct tc_iovec iov;
	const int N = 4096;
	char *data;
	char *read;
	tc_file *tcf;

	Removev(&path, 1);

	data = (char *)getRandomBytes(5 * N);
	tc_iov4creation(&iov, path, 5 * N, data);

	EXPECT_OK(tc_writev(&iov, 1, false));

	read = (char *)malloc(5 * N);
	EXPECT_NOTNULL(read);

	tcf = tc_open(path, O_RDONLY, 0);
	EXPECT_EQ(0, tc_fseek(tcf, 0, SEEK_CUR));
	EXPECT_NOTNULL(tcf);
	tc_iov2file(&iov, tcf, TC_OFFSET_CUR, N, read);
	EXPECT_OK(tc_readv(&iov, 1, false));
	EXPECT_EQ(N, tc_fseek(tcf, 0, SEEK_CUR));

	iov.data = read + N;
	EXPECT_OK(tc_readv(&iov, 1, false));
	EXPECT_EQ(2 * N, tc_fseek(tcf, 0, SEEK_CUR));

	EXPECT_EQ(3 * N, tc_fseek(tcf, N, SEEK_CUR));
	iov.data = read + 3 * N;
	EXPECT_OK(tc_readv(&iov, 1, false));

	EXPECT_EQ(2 * N, tc_fseek(tcf, 2 * N, SEEK_SET));
	iov.data = read + 2 * N;
	EXPECT_OK(tc_readv(&iov, 1, false));

	EXPECT_EQ(4 * N, tc_fseek(tcf, -N, SEEK_END));
	iov.data = read + 4 * N;
	EXPECT_OK(tc_readv(&iov, 1, false));
	EXPECT_TRUE(iov.is_eof);

	EXPECT_EQ(0, memcmp(data, read, 5 * N));

	free(data);
	free(read);
	tc_close(tcf);
}

TYPED_TEST_P(TcTest, SuccessiveWrites)
{
	const char *path = "SuccesiveWrites.dat";
	char *data = (char *)getRandomBytes(16_KB);
	/**
	 * open file one for actual writing
	 * other descriptor to verify
	 */
	tc_file *tcf = tc_open(path, O_RDWR | O_CREAT, 0755);
	EXPECT_NOTNULL(tcf);
	tc_file *tcf2 = tc_open(path, O_RDONLY, 0);
	EXPECT_NE(tcf->fd, tcf2->fd);

	struct tc_iovec iov;
	tc_iov2file(&iov, tcf, TC_OFFSET_CUR, 4_KB, data);
	EXPECT_OK(tc_writev(&iov, 1, false));
	tc_iov2file(&iov, tcf, TC_OFFSET_CUR, 4_KB, data + 4_KB);
	EXPECT_OK(tc_writev(&iov, 1, false));

	char *readbuf = (char *)malloc(16_KB);
	tc_iov2file(&iov, tcf2, 0, 8_KB, readbuf);
	EXPECT_OK(tc_readv(&iov, 1, false));
	EXPECT_EQ(iov.length, 8_KB);
	EXPECT_EQ(0, memcmp(data, readbuf, 8_KB));

	tc_iov2file(&iov, tcf, TC_OFFSET_CUR, 8_KB, data + 8_KB);
	EXPECT_OK(tc_writev(&iov, 1, false));

	tc_iov2file(&iov, tcf2, 0, 16_KB, readbuf);
	EXPECT_OK(tc_readv(&iov, 1, false));
	EXPECT_EQ(iov.length, 16_KB);
	EXPECT_EQ(0, memcmp(data, readbuf, 16_KB));

	tc_close(tcf);
	tc_close(tcf2);
	free(data);
	free(readbuf);
}

static char *getRandomBytes(int N)
{
	int fd;
	char *buf;
	ssize_t ret;
	ssize_t n;

	buf = (char *)malloc(N);
	if (!buf) {
		return NULL;
	}

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		free(buf);
		return NULL;
	}

	n = 0;
	while (n < N) {
		ret = read(fd, buf + n, MIN(16384, N - n));
		if (ret < 0) {
			free(buf);
			close(fd);
			return NULL;
		}
		n += ret;
	}

	close(fd);
	return buf;
}

static void CopyOrDupFiles(const char *dir, bool copy, int nfiles)
{
	const int N = 4096;
	std::vector<struct tc_extent_pair> pairs(nfiles);
	std::vector<struct tc_iovec> iovs(nfiles);
	std::vector<struct tc_iovec> read_iovs(nfiles);
	std::vector<std::string> src_paths(nfiles);
	std::vector<std::string> dst_paths(nfiles);
	char buf[PATH_MAX];

	EXPECT_TRUE(tc_rm_recursive(dir));
	EXPECT_OK(tc_ensure_dir(dir, 0755, NULL));

	for (int i = 0; i < nfiles; ++i) {
		src_paths[i].assign(
		    buf, snprintf(buf, PATH_MAX, "%s/src-%d.txt", dir, i));
		dst_paths[i].assign(
		    buf, snprintf(buf, PATH_MAX, "%s/dst-%d.txt", dir, i));
		tc_fill_extent_pair(&pairs[i], src_paths[i].c_str(), 0,
				    dst_paths[i].c_str(), 0, N);

		tc_iov4creation(&iovs[i], pairs[i].src_path, N,
				getRandomBytes(N));
		EXPECT_NOTNULL(iovs[i].data);

		tc_iov2path(&read_iovs[i], pairs[i].dst_path, 0, N,
			    (char *)malloc(N));
		EXPECT_NOTNULL(read_iovs[i].data);
	}

	EXPECT_OK(tc_writev(iovs.data(), nfiles, false));

	// copy or move files
	if (copy) {
		EXPECT_OK(tc_copyv(pairs.data(), nfiles, false));
	} else {
		EXPECT_OK(tc_dupv(pairs.data(), nfiles, false));
	}

	EXPECT_OK(tc_readv(read_iovs.data(), nfiles, false));

	compare_content(iovs.data(), read_iovs.data(), nfiles);

	for (int i = 0; i < nfiles; ++i) {
		free(iovs[i].data);
		free(read_iovs[i].data);
	}
}

TYPED_TEST_P(TcTest, CopyFiles)
{
	SCOPED_TRACE("CopyFiles");
	CopyOrDupFiles("TestCopy", true, 2);
	CopyOrDupFiles("TestCopy", true, 64);
}

TYPED_TEST_P(TcTest, DupFiles)
{
	SCOPED_TRACE("DupFiles");
	CopyOrDupFiles("TestDup", false, 2);
	CopyOrDupFiles("TestDup", false, 64);
}

TYPED_TEST_P(TcTest, CopyLargeDirectory)
{
	int i;
	int count;
	struct tc_attrs *contents;
	struct tc_attrs_masks masks = TC_ATTRS_MASK_NONE;
	struct tc_extent_pair *dir_copy_pairs = NULL;
	const char **oldpaths = NULL;
	const char **newpaths = NULL;
	struct tc_attrs *copied_attrs;
	char *dst_path;
	int file_count = 0;
	//Cannot be larger than 9999 or will not fit in str
	#define FILE_COUNT 10
	#define FILE_LENGTH_BYTES (100)
	struct tc_iovec iov[FILE_COUNT];

	EXPECT_OK(tc_ensure_dir("TcTest-CopyLargeDirectory", 0755, NULL));
	EXPECT_OK(tc_ensure_dir("TcTest-CopyLargeDirectory-Dest", 0755, NULL));

	for (i = 0; i < FILE_COUNT; i++) {
		char *path = (char*) alloca(PATH_MAX);
		char *str = (char*) alloca(5);
		sprintf(str, "%d", i);
		tc_path_join("TcTest-CopyLargeDirectory", str, path, PATH_MAX);
		tc_iov4creation(&iov[i], path, FILE_LENGTH_BYTES,
				getRandomBytes(FILE_LENGTH_BYTES));
		EXPECT_NOTNULL(iov[i].data);
	}
	EXPECT_OK(tc_writev(iov, FILE_COUNT, false));

	masks.has_mode = true;

	EXPECT_OK(tc_listdir("TcTest-CopyLargeDirectory", masks, 0, true,
			     &contents, &count));

	dir_copy_pairs = (struct tc_extent_pair *)alloca(
	    sizeof(struct tc_extent_pair) * count);
	copied_attrs =
	    (struct tc_attrs *)alloca(sizeof(struct tc_attrs) * count);

	for (i = 0; i < count; i++) {
		dst_path = (char *) malloc(sizeof(char) * PATH_MAX);
		const char *dst_suffix = contents[i].file.path;

		while (*dst_suffix++ != '/')

			tc_path_join("TcTest-CopyLargeDirectory-Dest",
				     dst_suffix, dst_path, PATH_MAX);

		if (!S_ISDIR(contents[i].mode)) {
			dir_copy_pairs[file_count].src_path =
			    contents[i].file.path;
			dir_copy_pairs[file_count].dst_path = dst_path;
			dir_copy_pairs[file_count].src_offset = 0;
			dir_copy_pairs[file_count].dst_offset = 0;
			dir_copy_pairs[file_count].length = 0;

			file_count++;
		} else {
			EXPECT_OK(tc_ensure_dir (dst_path, 0755, NULL));
			free(dst_path);
		}

	}


	EXPECT_OK(tc_copyv(dir_copy_pairs, file_count, false));
	for (i = 0; i < file_count; i++) {
		free((char *) dir_copy_pairs[i].dst_path);
	}
}

TYPED_TEST_P(TcTest, RecursiveCopyDirWithSymlinks)
{
#define TCT_RCD_DIR "RecursiveCopyDirWithSymlinks"
	tc_rm_recursive(TCT_RCD_DIR);
	tc_rm_recursive("RCDest");
	EXPECT_OK(tc_ensure_dir(TCT_RCD_DIR, 0755, NULL));
	const int NFILES = 8;
	const char * files[NFILES];
	for (int i = 0; i < NFILES; ++i) {
		files[i] =
		    new_auto_path(TCT_RCD_DIR "/file-%d", i);
	}
	tc_touchv(files, NFILES, false);
	EXPECT_EQ(0, tc_symlink("file-0", TCT_RCD_DIR "/link"));

	EXPECT_OK(
	    tc_cp_recursive(TCT_RCD_DIR, "RCDest", false));
	char buf[PATH_MAX];
	EXPECT_EQ(0, tc_readlink("RCDest/link", buf, PATH_MAX));
	EXPECT_STREQ("file-0", buf);
#undef TCT_RCD_DIR
}

TYPED_TEST_P(TcTest, CopyFirstHalfAsSecondHalf)
{
	const int N = 8096;
	struct tc_extent_pair pairs[2];
	struct tc_iovec iov;
	struct tc_iovec read_iov;

	pairs[0].src_path = "OriginalFile.txt";
	pairs[0].src_offset = 0;
	pairs[0].dst_path = "ReversedFile.txt";
	pairs[0].dst_offset = N / 2;
	pairs[0].length = N / 2;

	pairs[1].src_path = "OriginalFile.txt";
	pairs[1].src_offset = N / 2;
	pairs[1].dst_path = "ReversedFile.txt";
	pairs[1].dst_offset = 0;
	pairs[1].length = 0;  // 0 means from src_offset to EOF, i.e., N/2

	// create source files
	tc_iov4creation(&iov, pairs[0].src_path, N, getRandomBytes(N));
	EXPECT_NOTNULL(iov.data);
	EXPECT_OK(tc_writev(&iov, 1, false));

	// remove dest files
	Removev(&pairs[0].dst_path, 1);

	// reverse a file using copy
	EXPECT_OK(tc_copyv(pairs, 2, false));

	tc_iov2path(&read_iov, pairs[1].dst_path, 0, N, (char *)malloc(N));
	EXPECT_NOTNULL(read_iov.data);

	EXPECT_OK(tc_readv(&read_iov, 1, false));

	EXPECT_EQ(0, memcmp(iov.data, read_iov.data + N / 2, N / 2));
	EXPECT_EQ(0, memcmp(iov.data + N / 2, read_iov.data, N / 2));

	free(iov.data);
	free(read_iov.data);
}

TYPED_TEST_P(TcTest, CopyManyFilesDontFitInOneCompound)
{
	const int NFILES = 64;
	struct tc_extent_pair pairs[NFILES];
	for (int i = 0; i < NFILES; ++i) {
		char *path = (char *)alloca(PATH_MAX);
		snprintf(path, PATH_MAX, "CopyMany/a%d/b/c/d/e/f/g/h", i);
		tc_ensure_dir(path, 0755, NULL);

		snprintf(path, PATH_MAX, "CopyMany/a%d/b/c/d/e/f/g/h/foo", i);
		tc_touch(path, 4_KB);

		char *dest_file = (char *)alloca(PATH_MAX);
		snprintf(dest_file, PATH_MAX, "CopyMany/foo%d", i);
		tc_fill_extent_pair(&pairs[i], path, 0, dest_file, 0, 0);
	}

	EXPECT_OK(tc_copyv(pairs, NFILES, false));
}

TYPED_TEST_P(TcTest, ListAnEmptyDirectory)
{
	const char *PATH = "TcTest-EmptyDir";
	tc_attrs *contents;
	int count;

	tc_ensure_dir(PATH, 0755, NULL);
	EXPECT_OK(
	    tc_listdir(PATH, TC_ATTRS_MASK_ALL, 1, false, &contents, &count));
	EXPECT_EQ(0, count);
	EXPECT_EQ(NULL, contents);
}

/* Get "cannot access" error when listing 2nd-level dir.  */
TYPED_TEST_P(TcTest, List2ndLevelDir)
{
	const char *DIR_PATH = "TcTest-Dir/nested-dir";
	const char *FILE_PATH = "TcTest-Dir/nested-dir/foo";
	tc_attrs *attrs;
	int count;

	tc_ensure_dir(DIR_PATH, 0755, NULL);
	tc_touch(FILE_PATH, 0);
	EXPECT_OK(
	    tc_listdir(DIR_PATH, TC_ATTRS_MASK_ALL, 1, false, &attrs, &count));
	EXPECT_EQ(1, count);
	EXPECT_EQ(0, attrs->size);
	tc_free_attrs(attrs, count, true);
}

TYPED_TEST_P(TcTest, ShuffledRdWr)
{
	const char *PATH = "TcTest-ShuffledRdWr.dat";
	const int N = 8;  /* size of iovs */
	struct tc_iovec iovs[N];
	const int S = 4096;
	tc_touch(PATH, N * S);

	char *data1 = getRandomBytes(N * S);
	char *data2 = (char *)malloc(N * S);
	std::vector<int> offsets(N);
	std::iota(offsets.begin(), offsets.end(), 0);
	std::mt19937 rng(8887);
	for (int i = 0; i < 10; ++i) { // repeat for 10 times
		for (int n = 0; n < N; ++n) {
			tc_iov2path(&iovs[n], PATH, offsets[n] * S, S,
				    data1 + offsets[n] * S);
		}
		EXPECT_OK(tc_writev(iovs, N, false));

		for (int n = 0; n < N; ++n) {
			iovs[n].data = data2 + offsets[n] * S;
		}
		EXPECT_OK(tc_readv(iovs, N, false));
		EXPECT_EQ(0, memcmp(data1, data2, N * S));

		std::shuffle(offsets.begin(), offsets.end(), rng);
	}

	free(data1);
	free(data2);
}

TYPED_TEST_P(TcTest, ParallelRdWrAFile)
{
	const char *PATH = "TcTest-ParallelRdWrAFile.dat";
	const int T = 6;  /* # of threads */
	const int S = 4096;
	tc_touch(PATH, T * S);

	struct tc_iovec iovs[T];
	char *data1 = getRandomBytes(T * S);
	char *data2 = (char *)malloc(T * S);
	for (int i = 0; i < 1; ++i) { // repeat for 10 times
		for (int t = 0; t < T; ++t) {
			tc_iov2path(&iovs[t], PATH, t * S, S, data1 + t * S);
		}
		DoParallel(T, [&iovs](int i) {
			EXPECT_OK(tc_writev(&iovs[i], 1, false));
		});

		for (int t = 0; t < T; ++t) {
			iovs[t].data = data2 + t * S;
		}
		DoParallel(T, [&iovs](int i) {
			EXPECT_OK(tc_readv(&iovs[i], 1, false));
		});
		EXPECT_EQ(0, memcmp(data1, data2, T * S));
	}

	free(data1);
	free(data2);
}

TYPED_TEST_P(TcTest, RdWrLargeThanRPCLimit)
{
	struct tc_iovec iov;
	char* data1 = getRandomBytes(2_MB);
	tc_iov4creation(&iov, "TcTest-WriteLargeThanRPCLimit.dat", 2_MB, data1);

	EXPECT_OK(tc_writev(&iov, 1, false));
	EXPECT_EQ(2_MB, iov.length);

	char* data2 = (char *)malloc(2_MB);
	iov.is_creation = false;
	iov.data = data2;
	for (size_t s = 8_KB; s <= 2_MB; s += 8_KB) {
		iov.length = s;
		EXPECT_OK(tc_readv(&iov, 1, false));
		EXPECT_EQ(iov.length == 2_MB, iov.is_eof);
		EXPECT_EQ(s, iov.length);
		EXPECT_EQ(0, memcmp(data1, data2, s));
		if (s % 128_KB == 0)
			fprintf(stderr, "read size: %llu\n", s);
	}

	free(data1);
	free(data2);
}

TYPED_TEST_P(TcTest, CompressDeepPaths)
{
	const char *PATHS[] = { "TcTest-CompressDeepPaths/a/b/c0/001.dat",
				"TcTest-CompressDeepPaths/a/b/c0/002.dat",
				"TcTest-CompressDeepPaths/a/b/c1/001.dat",
				"TcTest-CompressDeepPaths/a/b/c1/002.dat",
				"TcTest-CompressDeepPaths/a/b/c1/002.dat",
				"TcTest-CompressDeepPaths/a/b/c1/002.dat", };
	const int N = sizeof(PATHS)/sizeof(PATHS[0]);

	tc_ensure_dir("TcTest-CompressDeepPaths/a/b/c0", 0755, NULL);
	tc_ensure_dir("TcTest-CompressDeepPaths/a/b/c1", 0755, NULL);

	tc_unlinkv(PATHS, N);
	struct tc_iovec *iovs = (struct tc_iovec *)calloc(N, sizeof(*iovs));
	for (int i = 0; i < N; ++i) {
		if (i == 0 || strcmp(PATHS[i], PATHS[i-1])) {
			tc_iov4creation(&iovs[i], PATHS[i], 4_KB,
					new char[4_KB]);
		} else {
			tc_iov2path(&iovs[i], PATHS[i], 0, 4_KB,
				    new char[4_KB]);
		}
	}

	EXPECT_OK(tc_writev(iovs, N, false));
	for (int i = 0; i < N; ++i) {
		EXPECT_STREQ(iovs[i].file.path, PATHS[i]);
		delete[] iovs[i].data;
	}

	tc_attrs *attrs = new tc_attrs[N];
	for (int i = 0; i < N; ++i) {
		attrs[i].file = iovs[i].file;
		attrs[i].masks = TC_ATTRS_MASK_ALL;
	}
	EXPECT_OK(tc_getattrsv(attrs, N, false));

	free(iovs);
	delete[] attrs;
}

// Checked unnecessary SAVEFH and RESTOREFH are not used thanks to
// optimization.
TYPED_TEST_P(TcTest, CompressPathForRemove)
{
	tc_ensure_dir("TcTest-CompressPathForRemove/a/b/c/d1", 0755, NULL);
	tc_ensure_dir("TcTest-CompressPathForRemove/a/b/c/d2", 0755, NULL);
	const int FILES_PER_DIR = 8;
	tc_file *files = (tc_file *)alloca(FILES_PER_DIR * 2 * sizeof(tc_file));
	for (int i = 0; i < FILES_PER_DIR; ++i) {
		char *p1 = new_auto_path(
		    "TcTest-CompressPathForRemove/a/b/c/d1/%d", i);
		char *p2 = new_auto_path(
		    "TcTest-CompressPathForRemove/a/b/c/d2/%d", i);
		const char *paths[2] = {p1, p2};
		tc_touchv(paths, 2, 4_KB);
		files[i] = tc_file_from_path(p1);
		files[i + FILES_PER_DIR] = tc_file_from_path(p2);
	}
	EXPECT_OK(tc_removev(files, FILES_PER_DIR * 2, false));
}

TYPED_TEST_P(TcTest, SymlinkBasics)
{
	const char *TARGETS[] = { "TcTest-SymlinkBasics/001.file",
				  "TcTest-SymlinkBasics/002.file",
				  "TcTest-SymlinkBasics/003.file",
				  "TcTest-SymlinkBasics/004.file",
				  "TcTest-SymlinkBasics/005.file", };
	const char *LINKS[] = { "TcTest-SymlinkBasics/001.link",
				"TcTest-SymlinkBasics/002.link",
				"TcTest-SymlinkBasics/003.link",
				"TcTest-SymlinkBasics/004.link",
				"TcTest-SymlinkBasics/005.link", };
	const char *CONTENTS[] = { "001.file", "002.file", "003.file",
				   "004.file", "005.file", };
	const int N = sizeof(TARGETS) / sizeof(TARGETS[0]);
	char **bufs = new char*[N];
	size_t *bufsizes = new size_t[N];

	EXPECT_OK(tc_ensure_dir("TcTest-SymlinkBasics", 0755, NULL));
	Removev(TARGETS, N);
	Removev(LINKS, N);

	for (int i = 0; i < N; ++i) {
		tc_touch(TARGETS[i], 4_KB);
		bufs[i] = new char[PATH_MAX];
		bufsizes[i] = PATH_MAX;
	}

	EXPECT_OK(tc_symlinkv(CONTENTS, LINKS, N, false));

	EXPECT_OK(tc_readlinkv(LINKS, bufs, bufsizes, N, false));

	for (int i = 0; i < N; ++i) {
		EXPECT_EQ(strlen(CONTENTS[i]), bufsizes[i]);
		EXPECT_EQ(0, strncmp(CONTENTS[i], bufs[i], bufsizes[i]));
		delete[] bufs[i];
	}
	delete[] bufs;
	delete[] bufsizes;
}

TYPED_TEST_P(TcTest, ManyLinksDontFitInOneCompound)
{
	const int NLINKS = 64;
	const char *targets[NLINKS];
	const char *links[NLINKS];
	char *bufs[NLINKS];
	size_t bufsizes[NLINKS];

	EXPECT_TRUE(tc_rm_recursive("ManyLinks"));
	for (int i = 0; i < NLINKS; ++i) {
		targets[i] = new_auto_path("ManyLinks/file%d", i);
		links[i] = new_auto_path("ManyLinks/a%d/b/c/d/e/f/h/link", i);
		tc_ensure_parent_dir(links[i]);
		bufs[i] = (char *)alloca(PATH_MAX);
		bufsizes[i] = PATH_MAX;
	}
	tc_touchv(targets, NLINKS, 1_KB);
	EXPECT_OK(tc_symlinkv(targets, links, NLINKS, false));
	EXPECT_OK(tc_readlinkv(links, bufs, bufsizes, NLINKS, false));
	for (int i = 0; i < NLINKS; ++i) {
		EXPECT_STREQ(targets[i], bufs[i]);
	}
}

TYPED_TEST_P(TcTest, WriteManyDontFitInOneCompound)
{
	const int NFILES = 64; // 64 * 8 == 512
	struct tc_iovec iovs[NFILES];
	const char *ROOTDIR = "WriteMany";

	EXPECT_TRUE(tc_rm_recursive(ROOTDIR));
	for (int i = 0; i < NFILES; ++i) {
		char *p =
		    new_auto_path("WriteMany/a%03d/b/c/d/e/f/g/h/file", i);
		tc_ensure_parent_dir(p);
		tc_iov4creation(&iovs[i], p, strlen(p), p);
	}
	EXPECT_OK(tc_writev(iovs, NFILES, false));
}

static bool listdir_test_cb(const struct tc_attrs *entry, const char *dir,
			    void *cbarg)
{
	std::set<std::string> *objs = (std::set<std::string> *)cbarg;
	objs->emplace(entry->file.path);
	return true;
}

TYPED_TEST_P(TcTest, RequestDoesNotFitIntoOneCompound)
{
	const int NFILES = 64; // 64 * 8 == 512
	const char *paths[NFILES];
	int flags[NFILES];
	struct tc_attrs attrs[NFILES];
	const char *new_paths[NFILES];
	struct tc_file_pair pairs[NFILES];
	const char *ROOTDIR = "DontFit";

	EXPECT_TRUE(tc_rm_recursive(ROOTDIR));
	for (int i = 0; i < NFILES; ++i) {
		paths[i] = new_auto_path("DontFit/a%03d/b/c/d/e/f/g/h/file", i);
		tc_ensure_parent_dir(paths[i]);
		flags[i] = O_WRONLY | O_CREAT;
		attrs[i].file = tc_file_from_path(paths[i]);
		new_paths[i] = new_auto_path("DontFit/file-%d", i);
		pairs[i].src_file = tc_file_from_path(paths[i]);
		pairs[i].dst_file = tc_file_from_path(new_paths[i]);
	}
	tc_file *files = tc_openv(paths, NFILES, flags, NULL);
	EXPECT_NOTNULL(files);
	EXPECT_OK(tc_closev(files, NFILES));
	EXPECT_OK(tc_getattrsv(attrs, NFILES, false));

	struct tc_attrs_masks listdir_mask = { .has_mode = true };
	std::set<std::string> objs;
	EXPECT_OK(tc_listdirv(&ROOTDIR, 1, listdir_mask, 0, true,
			      listdir_test_cb, &objs, false));
	std::set<std::string> expected;
	for (int i = 0; i < NFILES; ++i) {
		std::string p(paths[i]);
		size_t n = p.length();
		while (n != std::string::npos) {
			expected.emplace(p.data(), n);
			n = p.find_last_of('/', n - 1);
		}
	}
	expected.erase("DontFit");
	EXPECT_THAT(objs, testing::ContainerEq(expected));

	EXPECT_OK(tc_renamev(pairs, NFILES, false));
	EXPECT_OK(tc_unlinkv(new_paths, NFILES));
}

static bool is_same_stat(const struct stat *st1, const struct stat *st2)
{
	return st1->st_ino == st2->st_ino
	    && st1->st_mode == st2->st_mode
	    && st1->st_nlink == st2->st_nlink
	    && st1->st_uid == st2->st_uid
	    && st1->st_gid == st2->st_gid
	    && st1->st_rdev == st2->st_rdev
	    && st1->st_size == st2->st_size
	    && st1->st_mtime == st2->st_mtime
	    && st1->st_ctime == st2->st_ctime;
	    //&& st1->st_dev == st2->st_dev
	    //&& st1->st_blksize == st2->st_blksize
	    //&& st1->st_blocks == st2->st_blocks
}

TYPED_TEST_P(TcTest, TcStatBasics)
{
	const char *FPATH = "TcTest-TcStatFile.txt";
	const char *LPATH = "TcTest-TcStatLink.txt";

	tc_unlink(FPATH);
	tc_unlink(LPATH);
	tc_touch(FPATH, 4_KB);
	EXPECT_EQ(0, tc_symlink(FPATH, LPATH));

	struct stat st1;
	EXPECT_EQ(0, tc_stat(LPATH, &st1));

	struct stat st2;
	tc_file *tcf = tc_open(FPATH, O_RDONLY, 0);
	EXPECT_EQ(0, tc_fstat(tcf, &st2));
	EXPECT_TRUE(is_same_stat(&st1, &st2));
	tc_close(tcf);

	struct stat st3;
	EXPECT_EQ(0, tc_lstat(LPATH, &st3));
	EXPECT_TRUE(S_ISLNK(st3.st_mode));
	EXPECT_FALSE(is_same_stat(&st1, &st3));
}

TYPED_TEST_P(TcTest, TcRmBasic)
{
#define TCRM_PREFIX "/vfs0/tc_nfs4_test/TcRmBasic"
	EXPECT_OK(tc_ensure_dir(TCRM_PREFIX "/dir-a/subdir-a1", 0755, NULL));
	EXPECT_OK(tc_ensure_dir(TCRM_PREFIX "/dir-a/subdir-a2", 0755, NULL));
	EXPECT_OK(tc_ensure_dir(TCRM_PREFIX "/dir-b/subdir-b1", 0755, NULL));

	tc_touch(TCRM_PREFIX "/dir-a/subdir-a1/a1-file1", 4_KB);
	tc_touch(TCRM_PREFIX "/dir-a/subdir-a1/a1-file2", 4_KB);
	tc_touch(TCRM_PREFIX "/dir-a/subdir-a1/a1-file3", 4_KB);
	tc_touch(TCRM_PREFIX "/dir-a/subdir-a2/a2-file1", 4_KB);
	tc_touch(TCRM_PREFIX "/dir-a/subdir-a2/a2-file2", 4_KB);
	tc_touch(TCRM_PREFIX "/dir-b/subdir-b1/b1-file1", 4_KB);
	tc_touch(TCRM_PREFIX "/dir-b/subdir-b1/b1-file2", 4_KB);
	tc_touch(TCRM_PREFIX "/dir-b/subdir-b1/b1-file3", 4_KB);
	tc_touch(TCRM_PREFIX "/file1", 4_KB);
	tc_touch(TCRM_PREFIX "/file2", 4_KB);

	const char *objs[4] = {
		TCRM_PREFIX "/dir-a",
		TCRM_PREFIX "/dir-b",
		TCRM_PREFIX "/file1",
		TCRM_PREFIX "/file2",
	};

	EXPECT_OK(tc_rm(objs, 4, true));
#undef TCRM_PREFIX
}

/**
 * Test listing and removing a big directory.
 *
 * Wrap a big directory "RmMany/bb" with two small directories (i.e.,
 * "RmMany/aa" and "RmMany/cc") and make sure big directory are handled
 * correctly.
 */
TYPED_TEST_P(TcTest, TcRmManyFiles)
{
	EXPECT_OK(tc_ensure_dir("RmMany", 0755, NULL));
	EXPECT_OK(tc_ensure_dir("RmMany/aa", 0755, NULL));
	EXPECT_OK(tc_ensure_dir("RmMany/bb", 0755, NULL));
	tc_touch("RmMany/aa/foo", 1_KB);
	const int N_PER_CPD = 64;
	char *scratch = (char *)malloc(PATH_MAX * N_PER_CPD);
	for (int i = 0; i < 32; ++i) {
		const char *FILES[N_PER_CPD];
		for (int j = 0; j < N_PER_CPD; ++j) {
			char *p = scratch + j * PATH_MAX;
			snprintf(p, PATH_MAX, "RmMany/bb/file-%d-%d", i, j);
			FILES[j] = p;
		}
		tc_touchv(FILES, N_PER_CPD, 64);
	}
	free(scratch);
	EXPECT_OK(tc_ensure_dir("RmMany/cc", 0755, NULL));
	tc_touch("RmMany/cc/bar", 1_KB);
	EXPECT_TRUE(tc_rm_recursive("RmMany"));
}

TYPED_TEST_P(TcTest, TcRmRecursive)
{
	EXPECT_FALSE(tc_exists("NonExistDir"));
	EXPECT_TRUE(tc_rm_recursive("NonExistDir"));
}

REGISTER_TYPED_TEST_CASE_P(TcTest,
			   WritevCanCreateFiles,
			   TestFileDesc,
			   AttrsTestPath,
			   AttrsTestFileDesc,
			   AttrsTestSymlinks,
			   ListDirContents,
			   ListLargeDir,
			   ListDirRecursively,
			   RenameFile,
			   RemoveFileTest,
			   MakeDirectories,
			   MakeManyDirsDontFitInOneCompound,
			   Append,
			   SuccessiveReads,
			   SuccessiveWrites,
			   CopyFiles,
			   DupFiles,
			   CopyFirstHalfAsSecondHalf,
			   CopyManyFilesDontFitInOneCompound,
			   WriteManyDontFitInOneCompound,
			   ListAnEmptyDirectory,
			   List2ndLevelDir,
			   ShuffledRdWr,
			   ParallelRdWrAFile,
			   RdWrLargeThanRPCLimit,
			   CompressDeepPaths,
			   CompressPathForRemove,
			   SymlinkBasics,
			   ManyLinksDontFitInOneCompound,
			   TcStatBasics,
			   CopyLargeDirectory,
			   RecursiveCopyDirWithSymlinks,
			   TcRmBasic,
			   TcRmManyFiles,
			   TcRmRecursive,
			   RequestDoesNotFitIntoOneCompound);

typedef ::testing::Types<TcNFS4Impl, TcPosixImpl> TcImpls;
INSTANTIATE_TYPED_TEST_CASE_P(TC, TcTest, TcImpls);
