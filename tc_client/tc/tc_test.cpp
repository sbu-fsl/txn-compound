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

#include <gtest/gtest.h>

#include "tc_api.h"
#include "tc_helper.h"
#include "util/fileutil.h"
#include "log.h"

#define TCTEST_ERR(fmt, args...) LogCrit(COMPONENT_TC_TEST, fmt, ##args)
#define TCTEST_WARN(fmt, args...) LogWarn(COMPONENT_TC_TEST, fmt, ##args)
#define TCTEST_INFO(fmt, args...) LogInfo(COMPONENT_TC_TEST, fmt, ##args)
#define TCTEST_DEBUG(fmt, args...) LogDebug(COMPONENT_TC_TEST, fmt, ##args)

#define EXPECT_NOTNULL(x) EXPECT_TRUE(x != NULL) << #x << " is NULL"

/**
 * TODO(mchen): move to fileutil.h
 * Ensure the file does not exist
 * before test.
 */

/**
 * Ensure files or directories do not exist
 * before test.
 */
static void Removev(const char **paths, int count)
{
	int i = 0, r = 0;
	tc_file *files;

	files = (tc_file *)alloca(count * sizeof(tc_file));
	for (i = 0; i < count; ++i) {
		files[i] = tc_file_from_path(paths[i]);
	}

	/**
	 * FIXME: the compound may fail if files[i] does not exist whereas
	 * files[j] exists where i < j. So we ended up not deleting files[j].
	 */
	tc_removev(files, count, false);
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
		iov[i].file = files[i];
		iov[i].offset = offset;
		iov[i].length = N;
		iov[i].data = (void *)malloc(N);
		i++;
	}

	return iov;
}

static char *getRandomBytes(int N);

/**
 * Set the tc_iovec
 */
static tc_iovec *set_iovec_file_paths(const char **paths, int count,
				      int is_write, size_t offset)
{
	int i = 0;
	tc_iovec *user_arg = NULL;
	const int N = 4096;

	user_arg = (tc_iovec *)calloc(count, sizeof(tc_iovec));

	while (i < count) {
		if (paths[i] == NULL) {
			TCTEST_WARN(
			    "set_iovec_FilePath() failed for file : %s\n",
			    paths[i]);

			int indx = 0;
			while (indx < i) {
				free((user_arg + indx)->data);
				indx++;
			}
			free(user_arg);

			return NULL;
		}

		(user_arg + i)->file = tc_file_from_path(paths[i]);
		(user_arg + i)->offset = offset;

		(user_arg + i)->length = N;
		(user_arg + i)->data = (void *)malloc(N);

		if (is_write)
			(user_arg + i)->is_creation = 1;

		i++;
	}

	return user_arg;
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
	writev = set_iovec_file_paths(PATH, count, 1, 0);
	EXPECT_FALSE(writev == NULL);

	res = tc_writev(writev, count, false);
	EXPECT_TRUE(res.okay);

	struct tc_iovec *readv = NULL;
	readv = set_iovec_file_paths(PATH, count, 0, 0);
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
	tc_attrs *write_attr = NULL;
	tc_attrs *read_attr = NULL;

	while (i < count) {
		write_attr = write + i;
		read_attr = read + i;

		/* set tc_file */
		read_attr->file = write_attr->file;

		/* set masks */
		read_attr->masks = write_attr->masks;

		i++;
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

/**
 * List Directory Contents Test
 */
TYPED_TEST_P(TcTest, ListDirContents)
{
	tc_attrs *contents = (tc_attrs *)calloc(5, sizeof(tc_attrs));
	tc_attrs_masks masks = { 0 };
	int count = 0;

	masks.has_mode = 1;
	masks.has_size = 1;
	masks.has_atime = 1;
	masks.has_mtime = 1;
	masks.has_uid = 1;
	masks.has_gid = 1;
	masks.has_rdev = 1;
	masks.has_nlink = 1;
	masks.has_ctime = 1;

	contents->masks = masks;

	tc_res res = tc_listdir(".", masks, 5, &contents, &count);
	EXPECT_TRUE(res.okay);

	tc_attrs *read_attrs = (tc_attrs *)calloc(count, sizeof(tc_attrs));
	set_attr_masks(contents, read_attrs, count);

	res = tc_getattrsv(read_attrs, count, false);
	EXPECT_TRUE(res.okay);

	EXPECT_TRUE(compare(contents, read_attrs, count));

	free(contents);
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

	iov.file = tc_file_from_path(PATH);
	iov.offset = 0;
	iov.length = N;
	iov.data = data;
	iov.is_creation = true;

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
	iov.file = tc_file_from_path(path);
	iov.offset = 0;
	iov.length = 5 * N;
	iov.data = data;
	iov.is_creation = true;

	tcres = tc_writev(&iov, 1, false);
	EXPECT_TRUE(tcres.okay);

	read = (char *)malloc(5 * N);
	EXPECT_NOTNULL(read);

	tcf = tc_open(path, O_RDONLY, 0);
	EXPECT_NOTNULL(tcf);
	iov.file = *tcf;
	iov.offset = TC_OFFSET_CUR;
	iov.length = N;
	iov.data = read;
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
	iov[0].file = tc_file_from_path(pairs[0].src_path);
	iov[0].is_creation = true;
	iov[0].offset = 0;
	iov[0].length = N;
	iov[0].data = getRandomBytes(N);
	EXPECT_NOTNULL(iov[0].data);
	iov[1].file = tc_file_from_path(pairs[1].src_path);
	iov[1].is_creation = true;
	iov[1].offset = 0;
	iov[1].length = N;
	iov[1].data = getRandomBytes(N);
	EXPECT_NOTNULL(iov[1].data);
	tcres = tc_writev(iov, 2, false);
	EXPECT_TRUE(tcres.okay);

	// create empty dest files
	iov[0].file = tc_file_from_path(pairs[0].dst_path);
	iov[0].is_creation = true;
	iov[0].offset = 0;
	iov[0].length = 0;
	iov[0].data = NULL;
	iov[1].file = tc_file_from_path(pairs[1].dst_path);
	iov[1].is_creation = true;
	iov[1].offset = 0;
	iov[1].length = 0;
	iov[1].data = NULL;
	tcres = tc_writev(iov, 2, false);
	EXPECT_TRUE(tcres.okay);

	// copy files
	tcres = tc_copyv(pairs, 2, false);
	EXPECT_TRUE(tcres.okay);

	read_iov[0].file = tc_file_from_path(pairs[0].dst_path);
	read_iov[0].is_creation = false;
	read_iov[0].offset = 0;
	read_iov[0].length = N;
	read_iov[0].data = malloc(N);
	EXPECT_TRUE(read_iov[0].data);
	read_iov[1].file = tc_file_from_path(pairs[1].dst_path);
	read_iov[1].is_creation = false;
	read_iov[1].offset = 0;
	read_iov[1].length = N;
	read_iov[1].data = malloc(N);
	EXPECT_TRUE(read_iov[1].data);

	tcres = tc_readv(read_iov, 2, false);
	EXPECT_TRUE(tcres.okay);

	compare_content(iov, read_iov, 2);

	free(iov[0].data);
	free(iov[1].data);
	free(read_iov[0].data);
	free(read_iov[1].data);
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
			   CopyFiles);

typedef ::testing::Types<TcNFS4Impl, TcPosixImpl> TcImpls;
INSTANTIATE_TYPED_TEST_CASE_P(TC, TcTest, TcImpls);
