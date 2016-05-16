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
#include <fcntl.h>

#include <algorithm>
#include <list>
#include <random>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "tc_api.h"
#include "tc_helper.h"
#include "test_util.h"
#include "util/fileutil.h"
#include "log.h"

#define TCTEST_ERR(fmt, args...) LogCrit(COMPONENT_TC_TEST, fmt, ##args)
#define TCTEST_WARN(fmt, args...) LogWarn(COMPONENT_TC_TEST, fmt, ##args)
#define TCTEST_INFO(fmt, args...) LogInfo(COMPONENT_TC_TEST, fmt, ##args)
#define TCTEST_DEBUG(fmt, args...) LogDebug(COMPONENT_TC_TEST, fmt, ##args)

#define EXPECT_NOTNULL(x) EXPECT_TRUE(x != NULL) << #x << " is NULL"

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
	return tc_unlinkv(paths, count).okay;
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

void tc_touch(const char *path, int size)
{
	tc_iovec iov;
	tc_res tcres;

	tc_iov4creation(&iov, path, size, (size ? getRandomBytes(size) : NULL));
	tcres = tc_writev(&iov, 1, false);
	EXPECT_TRUE(tcres.okay) << "failed to create " << path;
	if (iov.data) {
		free(iov.data);
	}
}

/**
 * Set the tc_iovec
 */
static tc_iovec *set_iovec_file_paths(const char **paths, int count,
				      bool is_write, size_t offset)
{
	int i = 0;
	tc_iovec *iovs = NULL;
	const int N = 4096;

	iovs = (tc_iovec *)calloc(count, sizeof(tc_iovec));

	for (i = 0; i < count; ++i) {
		if (paths[i] == NULL) {
			TCTEST_WARN(
			    "set_iovec_FilePath() failed for file : %s\n",
			    paths[i]);
			free_iovec(iovs, i);
			return NULL;
		}
		tc_iov2path(&iovs[i], paths[i], offset, N, (char *)malloc(N));
		iovs[i].is_creation = is_write;
	}

	return iovs;
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
		tc_res res = tc_ensure_dir("/vfs0/tc_nfs4_test", 0755, NULL);
		EXPECT_TRUE(res.okay);
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
	const char *PATH[] = { "WritevCanCreateFiles1.txt",
			       "WritevCanCreateFiles2.txt",
			       "WritevCanCreateFiles3.txt",
			       "WritevCanCreateFiles4.txt" };
	char data[] = "abcd123";
	tc_res res;
	int count = 4;

	Removev(PATH, count);

	struct tc_iovec *writev = NULL;
	writev = set_iovec_file_paths(PATH, count, true, 0);
	EXPECT_FALSE(writev == NULL);

	res = tc_writev(writev, count, false);
	EXPECT_TRUE(res.okay);

	struct tc_iovec *readv = NULL;
	readv = set_iovec_file_paths(PATH, count, false, 0);
	EXPECT_FALSE(readv == NULL);

	res = tc_readv(readv, count, false);
	EXPECT_TRUE(res.okay);

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

	res = tc_writev(writev, N, false);
	EXPECT_TRUE(res.okay);

	struct tc_iovec *readv = NULL;
	readv = build_iovec(files, N, 0);
	EXPECT_FALSE(readv == NULL);

	res = tc_readv(readv, N, false);
	EXPECT_TRUE(res.okay);

	EXPECT_TRUE(compare_content(writev, readv, N));

	tc_closev(files, N);
	free_iovec(writev, N);
	free_iovec(readv, N);
}

/**
 * Compare the attributes once set, to check if set properly
 */

bool compare(tc_attrs *usr, tc_attrs *check, int count)
{
	int i = 0;
	tc_attrs *written = NULL;
	tc_attrs *read = NULL;

	while (i < count) {

		written = usr + i;
		read = check + i;

		if (written->masks.has_mode) {
			if (!written->mode & read->mode) {
				TCTEST_WARN("Mode does not match\n");
				TCTEST_WARN(" %d %d\n", written->mode,
					   read->mode);

				return false;
			}
		}

		if (written->masks.has_rdev) {
			if (memcmp((void *)&(written->rdev),
				   (void *)&(read->rdev), sizeof(read->rdev))) {
				TCTEST_WARN("rdev does not match\n");
				TCTEST_WARN(" %d %d\n", written->rdev,
					   read->rdev);

				return false;
			}
		}

		if (written->masks.has_nlink) {
			if (written->nlink != read->nlink) {
				TCTEST_WARN("nlink does not match\n");
				TCTEST_WARN(" %d %d\n", written->nlink,
					   read->nlink);

				return false;
			}
		}

		if (written->masks.has_uid) {
			if (written->uid != read->uid) {
				TCTEST_WARN("uid does not match\n");
				TCTEST_WARN(" %d %d\n", written->uid, read->uid);

				return false;
			}
		}

		if (written->masks.has_gid) {
			if (written->gid != read->gid) {
				TCTEST_WARN("gid does not match\n");
				TCTEST_WARN(" %d %d\n", written->gid, read->gid);

				return false;
			}
		}

		if (written->masks.has_atime) {
			if (memcmp((void *)&(written->atime),
				   (void *)&(read->atime),
				   sizeof(read->atime))) {
				TCTEST_WARN("atime does not match\n");
				TCTEST_WARN(" %d %d\n", written->atime,
					   read->atime);

				return false;
			}
		}

		if (written->masks.has_mtime) {
			if (memcmp((void *)&(written->mtime),
				   (void *)&(read->mtime),
				   sizeof(read->mtime))) {
				TCTEST_WARN("mtime does not match\n");
				TCTEST_WARN(" %d %d\n", written->mtime,
					   read->mtime);

				return false;
			}
		}

		i++;
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
	res = tc_setattrsv(attrs1, count, false);
	EXPECT_TRUE(res.okay);

	for (i = 0; i < count; ++i) {
		attrs2[i].masks = attrs1[i].masks;
	}
	res = tc_getattrsv(attrs2, count, false);
	EXPECT_TRUE(res.okay);

	EXPECT_TRUE(compare(attrs1, attrs2, count));

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
	tc_res res = { 0 };
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
	res = tc_setattrsv(attrs1, count, false);
	EXPECT_TRUE(res.okay);

	for (i = 0; i < count; ++i) {
		attrs2[i].masks = attrs1[i].masks;
	}
	res = tc_getattrsv(attrs2, count, false);
	EXPECT_TRUE(res.okay);

	EXPECT_TRUE(compare(attrs1, attrs2, count));

	tc_closev(tcfs, count);

	free(attrs1);
	free(attrs2);
}

static void free_listdir_attrs(tc_attrs *tcas, int count)
{
	int i;
	for (i = 0; i < count; ++i) {
		free((void *)tcas[i].file.path);
	}
	free(tcas);
}

/**
 * List Directory Contents Test
 */
TYPED_TEST_P(TcTest, ListDirContents)
{
	const char *DIR_PATH = "TcTest-ListDir";
	tc_attrs *contents;
	int count = 0;

	EXPECT_TRUE(tc_ensure_dir(DIR_PATH, 0755, 0).okay);
	tc_touch("TcTest-ListDir/file1.txt", 1);
	tc_touch("TcTest-ListDir/file2.txt", 2);
	tc_touch("TcTest-ListDir/file3.txt", 3);

	tc_res res =
	    tc_listdir(DIR_PATH, TC_ATTRS_MASK_ALL, 3, &contents, &count);
	EXPECT_TRUE(res.okay);
	EXPECT_EQ(3, count);

	tc_attrs *read_attrs = (tc_attrs *)calloc(count, sizeof(tc_attrs));
	read_attrs[0].file = tc_file_from_path("TcTest-ListDir/file1.txt");
	read_attrs[1].file = tc_file_from_path("TcTest-ListDir/file2.txt");
	read_attrs[2].file = tc_file_from_path("TcTest-ListDir/file3.txt");
	read_attrs[0].masks = read_attrs[1].masks = read_attrs[2].masks =
	    TC_ATTRS_MASK_ALL;
	res = tc_getattrsv(read_attrs, count, false);
	EXPECT_TRUE(res.okay);

	EXPECT_TRUE(compare(contents, read_attrs, count));

	free_listdir_attrs(contents, count);
	free(read_attrs);
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

	tc_res res = tc_renamev(files, 4, false);
	EXPECT_TRUE(res.okay);

	/* TODO use listdir to check src files no longer exist */

	free(files);
}

/**
 * Remove File Test
 */
TYPED_TEST_P(TcTest, RemoveFileTest)
{
	int i = 0;
	const char *path[] = { "rename1.txt", "rename2.txt",
			       "rename3.txt", "rename4.txt" };

	tc_file *file = (tc_file *)calloc(4, sizeof(tc_file));

	while (i < 4) {
		file[i] = tc_file_from_path(path[i]);

		i++;
	}

	tc_res res = tc_removev(file, 4, false);

	EXPECT_TRUE(res.okay);

	free(file);
}

/**
 * Make Directory Test
 */
TYPED_TEST_P(TcTest, MakeDirectory)
{
	int i = 0;
	mode_t mode[] = { S_IRWXU, S_IRUSR | S_IRGRP | S_IROTH,
			  S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH };
	const char *path[] = { "a", "b", "c" };
	struct tc_attrs dirs[3];

	Removev(path, 3);

	while (i < 3) {
		tc_set_up_creation(&dirs[i], path[i], 0755);
		i++;
	}

	tc_res res = tc_mkdirv(dirs, 3, false);

	EXPECT_TRUE(res.okay);
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
	tc_res res;
	struct tc_iovec iov;

	Removev(&PATH, 1);

	data = (char *)getRandomBytes(3 * N);
	data_read = (char *)malloc(3 * N);
	EXPECT_NOTNULL(data);
	EXPECT_NOTNULL(data_read);

	tc_iov4creation(&iov, PATH, N, data);

	res = tc_writev(&iov, 1, false);
	EXPECT_TRUE(res.okay);

	for (i = 0; i < 2; ++i) {
		iov.offset = TC_OFFSET_END;
		iov.data = data + N * (i + 1);
		iov.is_creation = false;
		res = tc_writev(&iov, 1, false);
		EXPECT_TRUE(res.okay);
	}

	iov.offset = 0;
	iov.length = 3 * N;
	iov.data = data_read;
	res = tc_readv(&iov, 1, false);
	EXPECT_TRUE(res.okay);
	EXPECT_TRUE(iov.is_eof);
	EXPECT_EQ(3 * N, iov.length);
	EXPECT_EQ(0, memcmp(data, data_read, 3 * N));

	free(data);
	free(data_read);
}

/**
 * Successive reads
 */
TYPED_TEST_P(TcTest, SuccesiveReads)
{
	const char *path = "TcTest-SuccesiveReads.txt";
	struct tc_iovec iov;
	const int N = 4096;
	char *data;
	char *read;
	tc_res tcres;
	tc_file *tcf;

	Removev(&path, 1);

	data = (char *)getRandomBytes(5 * N);
	tc_iov4creation(&iov, path, 5 * N, data);

	tcres = tc_writev(&iov, 1, false);
	EXPECT_TRUE(tcres.okay);

	read = (char *)malloc(5 * N);
	EXPECT_NOTNULL(read);

	tcf = tc_open(path, O_RDONLY, 0);
	EXPECT_NOTNULL(tcf);
	tc_iov2file(&iov, tcf, TC_OFFSET_CUR, N, read);
	tcres = tc_readv(&iov, 1, false);
	EXPECT_TRUE(tcres.okay);

	iov.data = read + N;
	tcres = tc_readv(&iov, 1, false);
	EXPECT_TRUE(tcres.okay);

	EXPECT_EQ(3 * N, tc_fseek(tcf, N, SEEK_CUR));
	iov.data = read + 3 * N;
	tcres = tc_readv(&iov, 1, false);
	EXPECT_TRUE(tcres.okay);

	EXPECT_EQ(2 * N, tc_fseek(tcf, 2 * N, SEEK_SET));
	iov.data = read + 2 * N;
	tcres = tc_readv(&iov, 1, false);
	EXPECT_TRUE(tcres.okay);

	EXPECT_EQ(4 * N, tc_fseek(tcf, -N, SEEK_END));
	iov.data = read + 4 * N;
	tcres = tc_readv(&iov, 1, false);
	EXPECT_TRUE(tcres.okay);
	EXPECT_TRUE(iov.is_eof);

	EXPECT_EQ(0, memcmp(data, read, 5 * N));

	free(data);
	free(read);
	tc_close(tcf);
}

/**
 * Successive writes
 */
TYPED_TEST_P(TcTest, SuccesiveWrites)
{
	//const char *path = "WritevCanCreateFiles10.txt";
	//int fd[2], i = 0, N = 4096;
	//off_t offset = 0;
	//void *data = calloc(1, N);
	//tc_res res;

	/*
	 * open file one for actual writing
	 * other descriptor to verify
	 */
	//fd[0] = open(path, O_WRONLY | O_CREAT);
	//fd[1] = open(path, O_RDONLY);
	//EXPECT_FALSE(fd[0] < 0);
	//EXPECT_FALSE(fd[1] < 0);

	//struct tc_iovec *writev = NULL;
	//writev = build_iovec(fd, 1, TC_OFFSET_CUR);
	//EXPECT_FALSE(writev == NULL);

	//while (i < 4) {
		//[> get the current offset of the file <]
		//offset = lseek(fd[0], 0, SEEK_CUR);

		//free(writev->data);
		//writev->data = (void *)malloc(N);

		//res = tc_writev(writev, 1, false);
		//EXPECT_TRUE(res.okay);

		//TCTEST_WARN("Test read from offset : %d\n", offset);

		//[> read the data from the file from the same offset <]
		//int error = pread(fd[1], data, writev->length, offset);
		//EXPECT_FALSE(error < 0);

		//[> compare data written with just read data from the file <]
		//error = memcmp(data, writev->data, writev->length);
		//EXPECT_TRUE(error == 0);

		//i++;
	//}

	//free(data);
	//free_iovec(writev, 1);

	//RemoveFile(&path, 1);
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

TYPED_TEST_P(TcTest, CopyFiles)
{
	const int N = 16 * 1024;
	struct tc_extent_pair pairs[2];
	struct tc_iovec iov[2];
	struct tc_iovec read_iov[2];
	tc_res tcres;

	pairs[0].src_path = "SourceFile1.txt";
	pairs[0].src_offset = 0;
	pairs[0].dst_path = "DestinationFile1.txt";
	pairs[0].dst_offset = 0;
	pairs[0].length = N;

	pairs[1].src_path = "SourceFile2.txt";
	pairs[1].src_offset = 0;
	pairs[1].dst_path = "DestinationFile2.txt";
	pairs[1].dst_offset = 0;
	pairs[1].length = N;

	// create source files
	tc_iov4creation(&iov[0], pairs[0].src_path, N, getRandomBytes(N));
	EXPECT_NOTNULL(iov[0].data);
	tc_iov4creation(&iov[1], pairs[1].src_path, N, getRandomBytes(N));
	EXPECT_NOTNULL(iov[1].data);
	tcres = tc_writev(iov, 2, false);
	EXPECT_TRUE(tcres.okay);

	// remove dest files
	Removev(&pairs[0].dst_path, 1);
	Removev(&pairs[1].dst_path, 1);

	// copy files
	tcres = tc_copyv(pairs, 2, false);
	EXPECT_TRUE(tcres.okay);

	tc_iov2path(&read_iov[0], pairs[0].dst_path, 0, N, (char *)malloc(N));
	EXPECT_NOTNULL(read_iov[0].data);
	tc_iov2path(&read_iov[1], pairs[1].dst_path, 0, N, (char *)malloc(N));
	EXPECT_NOTNULL(read_iov[1].data);

	tcres = tc_readv(read_iov, 2, false);
	EXPECT_TRUE(tcres.okay);

	compare_content(iov, read_iov, 2);

	free(iov[0].data);
	free(iov[1].data);
	free(read_iov[0].data);
	free(read_iov[1].data);
}

TYPED_TEST_P(TcTest, ListAnEmptyDirectory)
{
	const char *PATH = "TcTest-EmptyDir";
	tc_attrs *contents;
	int count;
	tc_res tcres;

	tc_ensure_dir(PATH, 0755, NULL);
	tcres = tc_listdir(PATH, TC_ATTRS_MASK_ALL, 1, &contents, &count);
	EXPECT_EQ(0, count);
	free_listdir_attrs(contents, count);
}

/* Get "cannot access" error when listing 2nd-level dir.  */
TYPED_TEST_P(TcTest, List2ndLevelDir)
{
	const char *DIR_PATH = "TcTest-Dir/nested-dir";
	const char *FILE_PATH = "TcTest-Dir/nested-dir/foo";
	tc_res tcres;
	tc_attrs *attrs;
	int count;

	tc_ensure_dir(DIR_PATH, 0755, NULL);
	tc_touch(FILE_PATH, 0);
	tcres = tc_listdir(DIR_PATH, TC_ATTRS_MASK_ALL, 1, &attrs, &count);
	EXPECT_EQ(1, count);
	EXPECT_EQ(0, attrs->size);
	free_listdir_attrs(attrs, count);
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
		tc_res tcres = tc_writev(iovs, N, false);
		EXPECT_TRUE(tcres.okay);

		for (int n = 0; n < N; ++n) {
			iovs[n].data = data2 + offsets[n] * S;
		}
		tcres = tc_readv(iovs, N, false);
		EXPECT_TRUE(tcres.okay);
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
			tc_res tcres = tc_writev(&iovs[i], 1, false);
			EXPECT_TRUE(tcres.okay);
		});

		for (int t = 0; t < T; ++t) {
			iovs[t].data = data2 + t * S;
		}
		DoParallel(T, [&iovs](int i) {
			tc_res tcres = tc_readv(&iovs[i], 1, false);
			EXPECT_TRUE(tcres.okay);
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

	tc_res tcres = tc_writev(&iov, 1, false);
	EXPECT_TRUE(tcres.okay);
	EXPECT_EQ(2_MB, iov.length);

	char* data2 = (char *)malloc(2_MB);
	iov.is_creation = false;
	iov.data = data2;
	for (size_t s = 8_KB; s <= 2_MB; s += 8_KB) {
		iov.length = s;
		tcres = tc_readv(&iov, 1, false);
		EXPECT_TRUE(tcres.okay);
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

	tc_res tcres = tc_writev(iovs, N, false);
	EXPECT_TRUE(tcres.okay);
	for (int i = 0; i < N; ++i) {
		EXPECT_STREQ(iovs[i].file.path, PATHS[i]);
		delete[] iovs[i].data;
	}

	tc_attrs *attrs = new tc_attrs[N];
	for (int i = 0; i < N; ++i) {
		attrs[i].file = iovs[i].file;
		attrs[i].masks = TC_ATTRS_MASK_ALL;
	}
	tcres = tc_getattrsv(attrs, N, false);
	EXPECT_TRUE(tcres.okay);

	free(iovs);
	delete[] attrs;
}

REGISTER_TYPED_TEST_CASE_P(TcTest,
			   WritevCanCreateFiles,
			   TestFileDesc,
			   AttrsTestPath,
			   AttrsTestFileDesc,
			   ListDirContents,
			   RenameFile,
			   RemoveFileTest,
			   MakeDirectory,
			   Append,
			   SuccesiveReads,
			   SuccesiveWrites,
			   CopyFiles,
			   ListAnEmptyDirectory,
			   List2ndLevelDir,
			   ShuffledRdWr,
			   ParallelRdWrAFile,
			   RdWrLargeThanRPCLimit,
			   CompressDeepPaths);

typedef ::testing::Types<TcNFS4Impl, TcPosixImpl> TcImpls;
INSTANTIATE_TYPED_TEST_CASE_P(TC, TcTest, TcImpls);
