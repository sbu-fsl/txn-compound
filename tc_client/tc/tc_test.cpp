/**
 * XXX: To add a new test, don't forget to register the test in
 * REGISTER_TYPED_TEST_CASE_P().
 *
 * This file uses an advanced GTEST feature called Type-Parameterized Test,
 * which is documented at
 * https://github.com/google/googletest/blob/master/googletest/docs/V1_7_AdvancedGuide.md
 */
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <gtest/gtest.h>

#include "tc_api.h"

#define POSIX_WARN(fmt, args...) fprintf(stderr, "==posix-WARN==" fmt, ##args)

#define APPEND -1
#define CURRENT -2

/**
 * TODO(mchen): move to fileutil.h
 * Ensure the file does not exist
 * before test.
 */
static void RemoveFile(const char *path)
{
	int r = unlink(path);
	EXPECT_TRUE(r == 0 || errno == ENOENT);
}

/**
 * Ensure files does not exist
 * before test.
 */
static void RemoveFiles(const char **path, int count)
{
	int i = 0, r = 0;

	while (i < count) {
		r = unlink(path[i]);
		EXPECT_TRUE(r == 0 || errno == ENOENT);
		i++;
	}
}

/**
 * Ensure Directory does not exist
 * before test.
 */
static void RemoveDir(const char **path, int count)
{
	int i = 0, r = 0;

	while (i < count) {
		r = rmdir(path[i]);
		EXPECT_TRUE(r == 0 || r == ENOENT);
		i++;
	}
}

/**
 * Free the tc_iovec
 */

void clear_iovec(tc_iovec *user_arg, int count)
{
	int i = 0;

	while (i < count) {
		free((user_arg + i)->data);
		i++;
	}

	free(user_arg);
}

/**
 * Set the tc_iovec
 */
static tc_iovec *set_iovec_file_paths(const char **PATH, int count,
				      int is_write, int offset)
{
	int i = 0;
	tc_iovec *user_arg = NULL;
	const int N = 4096;

	user_arg = (tc_iovec *)calloc(count, sizeof(tc_iovec));

	while (i < count) {
		if (PATH[i] == NULL) {
			POSIX_WARN(
			    "set_iovec_FilePath() failed for file : %s\n",
			    PATH[i]);

			int indx = 0;
			while (indx < i) {
				free((user_arg + indx)->data);
				indx++;
			}
			free(user_arg);

			return NULL;
		}

		(user_arg + i)->file = tc_file_from_path(PATH[i]);
		(user_arg + i)->offset = offset;

		(user_arg + i)->length = N;
		(user_arg + i)->data = (void *)malloc(N);

		if (is_write)
			(user_arg + i)->is_creation = 1;

		i++;
	}

	return user_arg;
}

/**
 * Verify the data has been
 * written as specified
 */
bool compare_content(tc_iovec *writev, tc_iovec *readv, int count)
{
	int i = 0;

	while (i < count) {
		if (memcmp((writev + i)->data, (readv + i)->data,
			   (writev + i)->length))
			return false;

		i++;
	}

	return true;
}

class TcPosixImpl {
public:
	static void SetUpTestCase() {
		/* TODO: setup posix impl */
		POSIX_WARN("Global SetUp of Posix Impl\n");
		tc_init1("/etc/ganesha/tc.conf", "/var/log/tc.log");
	}
	static void TearDownTestCase() {
		POSIX_WARN("Global TearDown of Posix Impl\n");
	}
	static void SetUp() {
		POSIX_WARN("SetUp Posix Impl Test\n");
	}
	static void TearDown() {
		POSIX_WARN("TearDown Posix Impl Test\n");
	}
};

class TcNFS4Impl {
public:
	static void SetUpTestCase() {
		/* TODO: setup NFS4 impl */
		POSIX_WARN("Global SetUp of NFS4 Impl\n");
		tc_init1("/etc/ganesha/tc.conf", "/var/log/tc.log");
	}
	static void TearDownTestCase() {
		POSIX_WARN("Global TearDown of NFS4 Impl\n");
	}
	static void SetUp() {
		POSIX_WARN("SetUp NFS4 Impl Test\n");
	}
	static void TearDown() {
		POSIX_WARN("TearDown NFS4 Impl Test\n");
	}
};

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
	const char *PATH[] = { "/tmp/WritevCanCreateFiles1.txt",
			       "/tmp/WritevCanCreateFiles2.txt",
			       "/tmp/WritevCanCreateFiles3.txt",
			       "/tmp/WritevCanCreateFiles4.txt" };
	char data[] = "abcd123";
	tc_res res;
	int count = 4;

	RemoveFiles(PATH, count);

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

	clear_iovec(writev, count);
	clear_iovec(readv, count);
}

/**
 * Set the TC I/O vector
 */
static tc_iovec *set_iovec_fd(int *fd, int count, int offset)
{
	int i = 0, N = 4096;
	tc_iovec *user_arg = NULL;

	user_arg = (tc_iovec *)calloc(count, sizeof(tc_iovec));

	while (i < count) {
		if (fd[i] < 0) {
			POSIX_WARN(
			    "set_iovec_fd() failed for fd at index : %d\n",
			    fd[i]);

			int indx = 0;
			while (indx < i) {
				free((user_arg + indx)->data);
				indx++;
			}
			free(user_arg);

			return NULL;
		}

		(user_arg + i)->file.type = TC_FILE_DESCRIPTOR;
		(user_arg + i)->file.fd = fd[i];
		(user_arg + i)->offset = offset;
		(user_arg + i)->length = N;
		(user_arg + i)->data = (void *)malloc(N);

		i++;
	}

	return user_arg;
}

/**
 * TC-Read and Write test using
 * File Descriptor
 */
TYPED_TEST_P(TcTest, TestFileDesc)
{
	const char *PATH[] = { "/tmp/WritevCanCreateFiles1.txt",
			       "/tmp/WritevCanCreateFiles2.txt",
			       "/tmp/WritevCanCreateFiles3.txt",
			       "/tmp/WritevCanCreateFiles4.txt" };
	const int N = 7;
	char data[] = "abcd123";
	tc_res res;
	int i = 0, count = 4;
	int fd[count];
	int open_flags = O_RDWR | O_CREAT;

	RemoveFiles(PATH, 4);

	while (i < count) {
		fd[i] = open(PATH[i], open_flags);
		if (fd[i] < 0)
			POSIX_WARN("open failed for file %s\n", PATH[i]);
		i++;
	}

	struct tc_iovec *writev = NULL;
	writev = set_iovec_fd(fd, count, 0);
	EXPECT_FALSE(writev == NULL);

	res = tc_writev(writev, count, false);
	EXPECT_TRUE(res.okay);

	struct tc_iovec *readv = NULL;
	readv = set_iovec_fd(fd, count, 0);
	EXPECT_FALSE(readv == NULL);

	res = tc_readv(readv, count, false);
	EXPECT_TRUE(res.okay);

	EXPECT_TRUE(compare_content(writev, readv, count));

	clear_iovec(writev, count);
	clear_iovec(readv, count);

	i = 0;
	while (i < count) {
		close(fd[i]);
		i++;
	}
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
				POSIX_WARN("Mode does not match\n");
				POSIX_WARN(" %d %d\n", written->mode,
					   read->mode);

				return false;
			}
		}

		if (written->masks.has_rdev) {
			if (memcmp((void *)&(written->rdev),
				   (void *)&(read->rdev), sizeof(read->rdev))) {
				POSIX_WARN("rdev does not match\n");
				POSIX_WARN(" %d %d\n", written->rdev,
					   read->rdev);

				return false;
			}
		}

		if (written->masks.has_nlink) {
			if (written->nlink != read->nlink) {
				POSIX_WARN("nlink does not match\n");
				POSIX_WARN(" %d %d\n", written->nlink,
					   read->nlink);

				return false;
			}
		}

		if (written->masks.has_uid) {
			if (written->uid != read->uid) {
				POSIX_WARN("uid does not match\n");
				POSIX_WARN(" %d %d\n", written->uid, read->uid);

				return false;
			}
		}

		if (written->masks.has_gid) {
			if (written->gid != read->gid) {
				POSIX_WARN("gid does not match\n");
				POSIX_WARN(" %d %d\n", written->gid, read->gid);

				return false;
			}
		}

		if (written->masks.has_atime) {
			if (memcmp((void *)&(written->atime),
				   (void *)&(read->atime),
				   sizeof(read->atime))) {
				POSIX_WARN("atime does not match\n");
				POSIX_WARN(" %d %d\n", written->atime,
					   read->atime);

				return false;
			}
		}

		if (written->masks.has_mtime) {
			if (memcmp((void *)&(written->mtime),
				   (void *)&(read->mtime),
				   sizeof(read->mtime))) {
				POSIX_WARN("mtime does not match\n");
				POSIX_WARN(" %d %d\n", written->mtime,
					   read->mtime);

				return false;
			}
		}

		i++;
	}

	return true;
}

/**
 * Set the TC Attributes
 */
static tc_attrs *set_tc_attrs(const char **PATH, int count, bool isPath)
{
	if (count > 3) {
		POSIX_WARN("count should be less than 4\n");
		return NULL;
	}

	tc_attrs *change_attr = (tc_attrs *)calloc(count, sizeof(tc_attrs));
	tc_attrs_masks masks[3] = { 0 };
	int i = 0;

	uid_t uid[] = { 2711, 456, 789 };
	gid_t gid[] = { 87, 4566, 2311 };
	mode_t mode[] = { S_IRUSR | S_IRGRP | S_IROTH,
			  S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH, S_IRWXU };
	size_t size[] = { 256, 56, 125 };
	time_t atime[] = { time(NULL), 1234, 567 };

	while (i < count) {

		if (PATH[i] == NULL) {
			free(change_attr);
			return NULL;
		}

		if (isPath) {
			(change_attr + i)->file.type = TC_FILE_PATH;
			(change_attr + i)->file.path = PATH[i];

		} else {
			(change_attr + i)->file.type = TC_FILE_DESCRIPTOR;
			(change_attr + i)->file.fd =
			    open(PATH[i], O_RDWR | O_CREAT);

			if ((change_attr + i)->file.fd < 0) {
				free(change_attr);
				return NULL;
			}
		}

		(change_attr + i)->mode = mode[i];
		(change_attr + i)->size = size[i];
		(change_attr + i)->uid = uid[i];
		(change_attr + i)->gid = gid[i];
		(change_attr + i)->atime = atime[i];
		(change_attr + i)->mtime = time(NULL);

		masks[i].has_mode = 1;
		masks[i].has_size = 1;
		masks[i].has_atime = 1;
		masks[i].has_mtime = 1;
		masks[i].has_uid = 1;
		masks[i].has_gid = 1;
		masks[i].has_rdev = 0;
		masks[i].has_nlink = 0;
		masks[i].has_ctime = 0;

		change_attr[i].masks = masks[i];

		i++;
	}

	return change_attr;
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
		read_attr->masks.has_mode = write_attr->masks.has_mode;
		read_attr->masks.has_size = write_attr->masks.has_size;
		read_attr->masks.has_atime = write_attr->masks.has_atime;
		read_attr->masks.has_mtime = write_attr->masks.has_mtime;
		read_attr->masks.has_uid = write_attr->masks.has_uid;
		read_attr->masks.has_gid = write_attr->masks.has_gid;
		read_attr->masks.has_rdev = write_attr->masks.has_rdev;
		read_attr->masks.has_nlink = write_attr->masks.has_nlink;
		read_attr->masks.has_ctime = write_attr->masks.has_ctime;

		i++;
	}
}

/**
 * TC-Set/Get Attributes test
 * using File Path
 */
TYPED_TEST_P(TcTest, AttrsTestPath)
{
	const char *PATH[] = { "/tmp/WritevCanCreateFiles1.txt",
			       "/tmp/WritevCanCreateFiles2.txt",
			       "/tmp/WritevCanCreateFiles3.txt" };
	tc_res res = { 0 };
	int count = 3;

	tc_attrs *write_attrs = NULL;
	write_attrs = set_tc_attrs(PATH, count, true);
	EXPECT_FALSE(write_attrs == NULL);

	res = tc_setattrsv(write_attrs, count, false);
	EXPECT_TRUE(res.okay);

	tc_attrs *read_attrs = (tc_attrs *)calloc(count, sizeof(tc_attrs));
	set_attr_masks(write_attrs, read_attrs, count);

	res = tc_getattrsv(read_attrs, count, false);
	EXPECT_TRUE(res.okay);

	EXPECT_TRUE(compare(write_attrs, read_attrs, count));

	free(write_attrs);
	free(read_attrs);
}

/*
 * TC-Set/Get Attributes test
 * using File Descriptor
 */
TYPED_TEST_P(TcTest, AttrsTestFileDesc)
{
	const char *PATH[] = { "/tmp/WritevCanCreateFiles4.txt",
			       "/tmp/WritevCanCreateFiles5.txt",
			       "/tmp/WritevCanCreateFiles6.txt" };
	tc_res res = { 0 };
	int i = 0, count = 3;

	RemoveFiles(PATH, count);

	tc_attrs *write_attrs = NULL;
	write_attrs = set_tc_attrs(PATH, count, false);
	EXPECT_FALSE(write_attrs == NULL);

	res = tc_setattrsv(write_attrs, count, false);
	EXPECT_TRUE(res.okay);

	tc_attrs *read_attrs = (tc_attrs *)calloc(count, sizeof(tc_attrs));
	set_attr_masks(write_attrs, read_attrs, count);

	res = tc_getattrsv(read_attrs, count, false);
	EXPECT_TRUE(res.okay);

	EXPECT_TRUE(compare(write_attrs, read_attrs, count));

	while (i < count) {
		close((read_attrs + i)->file.fd);
		i++;
	}

	free(write_attrs);
	free(read_attrs);
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

	tc_res res = tc_listdir("/tmp/", masks, 5, &contents, &count);
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
	const char *src_path[] = { "/tmp/WritevCanCreateFiles1.txt",
				   "/tmp/WritevCanCreateFiles2.txt",
				   "/tmp/WritevCanCreateFiles3.txt",
				   "/tmp/WritevCanCreateFiles4.txt" };

	const char *dest_path[] = { "/tmp/rename1.txt", "/tmp/rename2.txt",
				    "/tmp/rename3.txt", "/tmp/rename4.txt" };

	tc_file_pair *file = (tc_file_pair *)calloc(4, sizeof(tc_file_pair));

	while (i < 4) {
		file[i].src_file = tc_file_from_path(src_path[i]);
		file[i].dst_file = tc_file_from_path(dest_path[i]);

		i++;
	}

	tc_res res = tc_renamev(file, 4, false);

	EXPECT_TRUE(res.okay);

	free(file);
}

/**
 * Remove File Test
 */
TYPED_TEST_P(TcTest, RemoveFileTest)
{
	int i = 0;
	const char *path[] = { "/tmp/rename1.txt", "/tmp/rename2.txt",
			       "/tmp/rename3.txt", "/tmp/rename4.txt" };

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
	const char *path[] = { "/tmp/a", "/tmp/b", "/tmp/c" };

	tc_file *file = (tc_file *)calloc(3, sizeof(tc_file));

	RemoveDir(path, 3);

	while (i < 3) {

		(file + i)->path = path[i];
		(file + i)->type = TC_FILE_PATH;

		i++;
	}

	tc_res res = tc_mkdirv(file, mode, 3, false);

	EXPECT_TRUE(res.okay);

	free(file);
}

/**
 * Append test case
 */
TYPED_TEST_P(TcTest, Append)
{
	const char *PATH[] = { "/tmp/WritevCanCreateFiles6.txt" };
	int i = 0, count = 4, N = 4096;
	struct stat st;
	void *data = calloc(1, N);
	tc_res res;

	struct tc_iovec *writev = NULL;
	writev = set_iovec_file_paths(PATH, 1, 1, APPEND);
	EXPECT_FALSE(writev == NULL);

	int fd = open(PATH[0], O_RDONLY);
	EXPECT_FALSE(fd < 0);

	while (i < 4) {
		fstat(fd, &st);
		free(writev->data);
		writev->data = (void *)malloc(N);
		res = tc_writev(writev, 1, false);
		EXPECT_TRUE(res.okay);

		/* read the data from the file from the same offset */
		int error = pread(fd, data, writev->length, st.st_size);
		EXPECT_FALSE(error < 0);

		/* compare data written with just read data from the file */
		error = memcmp(data, writev->data, writev->length);
		EXPECT_TRUE(error == 0);

		i++;
	}

	free(data);
	clear_iovec(writev, 1);
}

/**
 * Successive reads
 */
TYPED_TEST_P(TcTest, SuccesiveReads)
{
	const char *path = "/tmp/WritevCanCreateFiles6.txt";
	int fd[2], i = 0, N = 4096;
	fd[0] = open(path, O_RDONLY);
	fd[1] = open(path, O_RDONLY);
	tc_res res;
	off_t offset = 0;

	void *data = calloc(1, N);

	struct tc_iovec *readv = NULL;
	readv = set_iovec_fd(fd, 1, CURRENT);
	EXPECT_FALSE(readv == NULL);

	/* move th current pointer by 10 bytes */
	lseek(fd[0], 10, SEEK_CUR);

	while (i < 4) {
		/* get the current offset of the file */
		offset = lseek(fd[0], 0, SEEK_CUR);

		res = tc_readv(readv, 1, false);
		EXPECT_TRUE(res.okay);

		POSIX_WARN("Test reading from offset : %d\n", offset);

		/* read from the file to compare the data */
		int error = pread(fd[1], data, readv->length, offset);
		EXPECT_FALSE(error < 0);

		/* compare the content read */
		error = memcmp(data, readv->data, readv->length);
		EXPECT_TRUE(error == 0);

		i++;
	}

	free(data);
	clear_iovec(readv, 1);

	RemoveFile(path);
}

/**
 * Successive writes
 */
TYPED_TEST_P(TcTest, SuccesiveWrites)
{
	const char *path = "/tmp/WritevCanCreateFiles10.txt";
	int fd[2], i = 0, N = 4096;
	off_t offset = 0;
	void *data = calloc(1, N);
	tc_res res;

	/*
	 * open file one for actual writing
	 * other descriptor to verify
	 */
	fd[0] = open(path, O_WRONLY | O_CREAT);
	fd[1] = open(path, O_RDONLY);
	EXPECT_FALSE(fd[0] < 0);
	EXPECT_FALSE(fd[1] < 0);

	struct tc_iovec *writev = NULL;
	writev = set_iovec_fd(fd, 1, CURRENT);
	EXPECT_FALSE(writev == NULL);

	while (i < 4) {
		/* get the current offset of the file */
		offset = lseek(fd[0], 0, SEEK_CUR);

		free(writev->data);
		writev->data = (void *)malloc(N);

		res = tc_writev(writev, 1, false);
		EXPECT_TRUE(res.okay);

		POSIX_WARN("Test read from offset : %d\n", offset);

		/* read the data from the file from the same offset */
		int error = pread(fd[1], data, writev->length, offset);
		EXPECT_FALSE(error < 0);

		/* compare data written with just read data from the file */
		error = memcmp(data, writev->data, writev->length);
		EXPECT_TRUE(error == 0);

		i++;
	}

	free(data);
	clear_iovec(writev, 1);

	RemoveFile(path);
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
			   SuccesiveWrites);

typedef ::testing::Types<TcPosixImpl, TcNFS4Impl> TcImpls;
INSTANTIATE_TYPED_TEST_CASE_P(TC, TcTest, TcImpls);
