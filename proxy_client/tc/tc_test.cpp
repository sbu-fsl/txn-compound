#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <gtest/gtest.h>

#include "tc_api.h"

#define POSIX_WARN(fmt, args...) fprintf(stderr, "==posix-WARN==" fmt, ## args)

// Ensure the file does not exist before test.
static void RemoveFile(const char **path, int count) {
	int i = 0, r = 0;

	while(i <  count) {
		r = unlink(path[i]);
		EXPECT_TRUE(r == 0 || r == ENOENT);
		i++;
	}

}

/*
 * Free the tc_iovec
 */

void clear_iovec(tc_iovec *user_arg, int count)
{
        int i=0;

        while(i < count) {
                free((user_arg+i)->data);
                i++;
        }

        free(user_arg);
}

/*
 * Set the tc_iovec
 */
static tc_iovec* set_iovec_FilePath(const char **PATH, int count, int is_write)
{
        int i = 0;
        tc_iovec *user_arg = NULL;

        user_arg = (tc_iovec *)calloc(count, sizeof(tc_iovec));

        while(i<count) {
                if(PATH[i] == NULL) {
                        POSIX_WARN("set_iovec_FilePath() failed for file : %s\n",
                                                  PATH[i]);

                        int indx = 0;
                        while(indx < i) {
                                free((user_arg + indx)->data);
                                indx++;
                        }
                        free(user_arg);

                        return NULL;
                }

		(user_arg + i)->file.type = FILE_PATH;
		(user_arg + i)->file.path = PATH[i];
                (user_arg + i)->offset = i * 7;
                (user_arg + i)->length = 7;
                (user_arg + i)->data = (void *)calloc(1, 8);

                if(is_write) {
			(user_arg + i)->is_creation = 1;
                        memcpy((user_arg + i)->data, "abcd123", 7);
		}

                i++;
        }

        return user_arg;
}

bool compare_content(tc_iovec *writev, tc_iovec *readv, int count)
{
	int i = 0;

	while(i < count) {
		if(memcmp((writev + i)->data, (readv + i)->data, (writev + i)->length))
			return false;

		i++;
	}

	return true;
}

TEST(tc_test, WritevCanCreateFiles) {
	const char* PATH[] = {"/tmp/WritevCanCreateFiles1.txt", "/tmp/WritevCanCreateFiles2.txt",
				"/tmp/WritevCanCreateFiles3.txt", "/tmp/WritevCanCreateFiles4.txt"};
	const int N = 7;
	char data[] = "abcd123";
	tc_res res;
	int count = 4;

	RemoveFile(PATH, count);

	struct tc_iovec *writev = NULL;
	writev = set_iovec_FilePath(PATH, count, 1);
	EXPECT_FALSE(writev == NULL);

	res = tc_writev(writev, count, false);
	EXPECT_TRUE(res.okay);

	struct tc_iovec *readv = NULL;
	readv = set_iovec_FilePath(PATH, count, 0);
	EXPECT_FALSE(readv == NULL);

	res = tc_readv(readv, count, false);
        EXPECT_TRUE(res.okay);

	EXPECT_TRUE(compare_content(writev, readv, count));

	clear_iovec(writev, count);
	clear_iovec(readv, count);
}

static tc_iovec* set_iovec_fd(int *fd, int count, int is_write)
{
        int i = 0;
        tc_iovec *user_arg = NULL;

        user_arg = (tc_iovec *)calloc(count, sizeof(tc_iovec));

        while(i < count) {
                if(fd[i] < 0) {
                        POSIX_WARN("set_iovec_fd() failed for fd at index : %d\n",
					fd[i]);

                        int indx = 0;
                        while(indx < i) {
                                free((user_arg + indx)->data);
                                indx++;
                        }
                        free(user_arg);

                        return NULL;
                }

                (user_arg + i)->file.type = FILE_DESCRIPTOR;
                (user_arg + i)->file.fd = fd[i];
                (user_arg + i)->offset = i * 7;
                (user_arg + i)->length = 7;
                (user_arg + i)->data = (void *)calloc(1, 8);

                if(is_write)
                        memcpy((user_arg + i)->data, "abcd123", 7);
                i++;
        }

	return user_arg;
}

TEST(tc_test, TestFileDesc) {
        const char* PATH[] = {"/tmp/WritevCanCreateFiles1.txt", "/tmp/WritevCanCreateFiles2.txt",
                                "/tmp/WritevCanCreateFiles3.txt", "/tmp/WritevCanCreateFiles4.txt"};
        const int N = 7;
        char data[] = "abcd123";
        tc_res res;
        int i=0, count = 4;
	int fd[count];
	int open_flags = O_RDWR | O_CREAT;

	RemoveFile(PATH, count);

	while(i < count) {
		fd[i] = open(PATH[i], open_flags);
		if(fd[i] < 0)
			POSIX_WARN("open failed for file %s\n", PATH[i]);
		i++;
	}

        struct tc_iovec *writev = NULL;
        writev = set_iovec_fd(fd, count, 1);
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
	while(i < count) {
                close(fd[i]);
                i++;
        }
}

/*
 * Compare the attributes once set, to check if set properly
 */

bool compare(tc_attrs *usr, tc_attrs *check, int count)
{
        int i=0;
        while(i <  count) {

                POSIX_WARN("file name : %s\n", (usr + i)->path);

                if((usr + i)->masks.has_mode) {
                        if(!((usr + i)->mode & (check + i)->mode)) {
                                POSIX_WARN("Mode set op failed\n");
                                POSIX_WARN(" %d %d\n", (usr+i)->mode, (check + i)->mode);

				return false;
                        }
                }

                if((usr + i)->masks.has_rdev) {
                        if(memcmp((void *)&((usr + i)->rdev), (void *)&((check + i)->rdev), sizeof((check + i)->rdev))) {
                                POSIX_WARN("rdev set op failed\n");
                                POSIX_WARN(" %d %d\n", (usr+i)->rdev, (check + i)->rdev);

                                return false;
                        }
                }

                if((usr + i)->masks.has_nlink) {
                        if((usr + i)->nlink == (check + i)->nlink) {
                                POSIX_WARN("nlink set op failed");
                                POSIX_WARN(" %d %d\n", (usr+i)->nlink, (check + i)->nlink);

                                return false;
                        }
                }

                if((usr + i)->masks.has_uid) {
                        if(memcmp((void *)&((usr + i)->uid),(void *) &((check + i)->uid), sizeof((check + i)->uid))) {
                                POSIX_WARN("uid set op failed\n");
                                POSIX_WARN(" %d %d\n", (usr+i)->uid, (check + i)->uid);

                                return false;
                        }
                }

                if((usr + i)->masks.has_gid) {
                        if(memcmp((void *)&((usr + i)->gid), (void *)&((check + i)->gid), sizeof((check + i)->gid))) {
                                POSIX_WARN("gid set op failed\n");
                                POSIX_WARN(" %d %d\n", (usr+i)->gid, (check + i)->gid);

                                return false;
                        }
                }

                if((usr + i)->masks.has_atime) {
                        if(memcmp((void *)&((usr + i)->atime), (void *)&((check + i)->atime), sizeof((check + i)->atime))) {
                                POSIX_WARN("atime set op failed\n");
                                POSIX_WARN(" %d %d\n", (usr+i)->atime, (check + i)->atime);

                                return false;
                        }
                }

                if((usr + i)->masks.has_mtime) {
                        if(memcmp((void *)&((usr + i)->mtime), (void *)&((check + i)->mtime), sizeof((check + i)->mtime))) {
                                POSIX_WARN("mtime failed\n");
                                POSIX_WARN(" %d %d\n", (usr+i)->mtime, (check + i)->mtime);

                                return false;
                        }
                }

                i++;
        }

        return true;
}


tc_attrs* set_tc_attrs(const char **PATH, int count)
{
        tc_attrs *change_attr = (tc_attrs *)calloc(count, sizeof(tc_attrs));
        tc_attrs_masks masks[3] = {0};
        int i = 0;

        uid_t uid[] = {2711, 456, 789};
        gid_t gid[] = {87, 4566, 2311};
        mode_t mode[] = {S_IRUSR|S_IRGRP|S_IROTH, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH, S_IRWXU};
        size_t size[] = {256, 56, 125};
        time_t atime[] = {time(NULL), 1234, 567};


        while(i < count) {

                if(PATH[i] == NULL) {
                        free(change_attr);
                        return NULL;
                }

                (change_attr + i)->path = PATH[i];
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

TEST(tc_test, AttrsTest) {
	const char* PATH[] = {"/tmp/WritevCanCreateFiles1.txt", "/tmp/WritevCanCreateFiles2.txt",
                                "/tmp/WritevCanCreateFiles3.txt"};
	tc_res res = {0};
	int i = 0, count = 3;

        struct tc_attrs *write_attrs = NULL;
	write_attrs = set_tc_attrs(PATH, count);
	EXPECT_FALSE(write_attrs == NULL);

        res = tc_setattrsv(write_attrs, count, false);
        EXPECT_TRUE(res.okay);

	struct tc_attrs *read_attrs = NULL;
        read_attrs = set_tc_attrs(PATH, count);
        EXPECT_FALSE(read_attrs == NULL);

	res = tc_getattrsv(read_attrs, count, false);
        EXPECT_TRUE(res.okay);

	EXPECT_TRUE(compare(write_attrs, read_attrs, count));

	free(write_attrs);
	free(read_attrs);
}

