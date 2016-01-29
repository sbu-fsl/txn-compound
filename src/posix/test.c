#include <ctype.h>
#include <ctype.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "fsal_types.h"
#include "fsal_api.h"
#include "fsal.h"
#include "FSAL/fsal_init.h"
#include "tc_api.h"

char* formattime(char* str, time_t val)
{
        strftime(str, 36, "%d.%m.%Y %H:%M:%S", localtime(&val));
        return str;
}

int test()
{
	struct tc_attrs *usr_attr = NULL;
	struct tc_attrs *cur_attr = NULL;

	/*************************************************************
	 ***************** Reads/Writes ******************************
	 *************************************************************
	 */

	struct tc_iovec *user_arg = NULL;
        struct tc_iovec *cur_arg = NULL;

	/*
	 * posix_readv read the specified files
	 */

	user_arg = malloc(4 * (sizeof(struct tc_iovec)));
        user_arg->path = "/home/garima/test/abcd";
        user_arg->offset = 0;
        user_arg->length = 256;
        user_arg->data = malloc(256);

        int i = 1;
        while (i < 4) {
                cur_arg = user_arg + i;
                cur_arg->path = "/home/garima/test/abcd";
                cur_arg->offset = i * 256;
                cur_arg->length = 256;
                cur_arg->data = malloc(256);
                i++;
        }

        LogDebug(COMPONENT_FSAL, "posix_readv() for abcd called\n");

        posix_readv(user_arg, 4, FALSE);

        LogDebug(COMPONENT_FSAL, "posix_readv() for abcd succesful\n");

        i = 0;
        while (i < 4) {
                cur_arg = user_arg + i;
                free(cur_arg->data);
                i++;
        }

        free(user_arg);

	/*
	 * posix_readv should fail with file not found error
	 */

	user_arg = malloc(4 * (sizeof(struct tc_iovec)));
        user_arg->path = "abcd1";
        user_arg->offset = 0;
        user_arg->length = 256;
        user_arg->data = malloc(256);
        cur_arg = user_arg + 1;
        cur_arg->path = "/home/garima/test/abcd";
        cur_arg->offset = 256;
        cur_arg->length = 256;
        cur_arg->data = malloc(256);
        cur_arg = user_arg + 2;
        cur_arg->path = NULL;
        cur_arg->offset = 0;
        cur_arg->length = 256;
        cur_arg->data = malloc(256);
        cur_arg = user_arg + 3;
        cur_arg->path = "/home/garima/test/abcd1";
        cur_arg->offset = 256;
        cur_arg->length = 256;
        cur_arg->data = malloc(256);

	LogDebug(COMPONENT_FSAL, "posix_readv() for abcd, abcd1 called\n");

        posix_readv(user_arg, 4, FALSE);
	
        LogDebug(COMPONENT_FSAL, "posix_readv() for abcd, abcd1 failed\n");

        i = 0;
        while (i < 4) {
                cur_arg = user_arg + i;
                free(cur_arg->data);
                i++;
        }

        free(user_arg);

	/*
	 * Test Sequential writes to the same file
	 */

        user_arg = malloc(4 * (sizeof(struct tc_iovec)));
        user_arg->path = "/home/garima/test/abcd";
        user_arg->offset = 0;
        user_arg->length = 5;
        user_arg->data = malloc(6);
        strcpy(user_arg->data, "a2345");
	
	i = 1;
        while (i < 4) {
                cur_arg = user_arg + i;
                cur_arg->path = "/home/garima/test/abcd";
                cur_arg->offset = i * 5;
                cur_arg->length = 5;
                cur_arg->data = malloc(6);
                strcpy(cur_arg->data, "a2345");
                i++;
        }

        LogDebug(COMPONENT_FSAL, "posix_writev() for abcd called\n");

        posix_writev(user_arg, 4, FALSE);

        LogDebug(COMPONENT_FSAL, "posix_writev() for abcd successful\n");

        i = 0;
        while (i < 4) {
                cur_arg = user_arg + i;
                free(cur_arg->data);
                i++;
        }

        free(user_arg);

	/*
	 * posix_writev failed, File not found error
	 */

	user_arg = malloc(4 * (sizeof(struct tc_iovec)));
        user_arg->path = "/home/garima/test/abcd1";
        user_arg->offset = 0;
        user_arg->length = 8;
        user_arg->data = malloc(9);
        strcpy(user_arg->data, "abcd1234");
        cur_arg = user_arg + 1;
        cur_arg->path = NULL;
        cur_arg->offset = 8;
        user_arg->length = 8;
        user_arg->data = malloc(9);
        strcpy(user_arg->data, "abcd1234");
        cur_arg = user_arg + 2;
        cur_arg->path = "abcd1";
        cur_arg->offset = 0;
        user_arg->length = 8;
        user_arg->data = malloc(9);
        strcpy(user_arg->data, "abcd1234");
        cur_arg = user_arg + 3;
        cur_arg->path = NULL;
        cur_arg->offset = 8;
        user_arg->length = 8;
        user_arg->data = malloc(9);
        strcpy(user_arg->data, "abcd1234");

        LogDebug(COMPONENT_FSAL, "posix_writev() for abcd, abcd1 called\n");

        posix_writev(user_arg, 4, FALSE);

        LogDebug(COMPONENT_FSAL, "posix_writev() for abcd, abcd1 failed\n");

        i = 0;
        while (i < 4) {
                cur_arg = user_arg + i;
                free(cur_arg->data);
                i++;
        }

	free(user_arg);


	/*************************************************************
	 ***************** Attributes ********************************
	 *************************************************************
	 */

	usr_attr = malloc(4 * sizeof(tc_attrs));
	usr_attr->path = "/home/garima/test/abcd";
	usr_attr->mode = 0777;
	usr_attr->size = 256;
	usr_attr->uid = 11;
	usr_attr->gid = 270;
	usr_attr->atime = 0;
	usr_attr->mtime = time(NULL);

	usr_attr->masks.has_mode = 1;
        usr_attr->masks.has_size = 1;
        usr_attr->masks.has_atime = 1;
        usr_attr->masks.has_mtime = 1;
        usr_attr->masks.has_uid = 1;
        usr_attr->masks.has_gid = 1;
	usr_attr->masks.has_rdev = 0;
	usr_attr->masks.has_nlink = 0;
	usr_attr->masks.has_ctime = 0;

	i=1;
	while(i<4) {
		
		cur_attr = usr_attr + i;
		cur_attr->path = NULL;
        	cur_attr->mode = S_IRUSR|S_IRGRP|S_IROTH;
        	cur_attr->size = 256;
        	cur_attr->uid = 4711;
        	cur_attr->gid = 2070;
        	cur_attr->atime = 1234;
        	cur_attr->mtime = time(NULL);

		i++;
	}

        LogDebug(COMPONENT_FSAL, "posix_setattrsv() for abcd called\n");

        posix_setattrsv(usr_attr, 4, FALSE);

        LogDebug(COMPONENT_FSAL, "posix_setattrsv() for abcd successful\n");

        free(usr_attr);

	/*
	 * Set Attributes fail, rdev bit should not be set
	 */

	usr_attr = malloc(4 * sizeof(tc_attrs));
        usr_attr->path = "/home/garima/test/abcd1";
	usr_attr->mode = 0777;
        usr_attr->size = 256;
        usr_attr->uid = 11;
        usr_attr->gid = 270;
        usr_attr->atime = 0;
        usr_attr->mtime = time(NULL);

	usr_attr->masks.has_mode = 1;
        usr_attr->masks.has_size = 1;
        usr_attr->masks.has_rdev = 1;
        usr_attr->masks.has_nlink = 0;
        usr_attr->masks.has_atime = 1;
        usr_attr->masks.has_mtime = 1;
        usr_attr->masks.has_uid = 1;
        usr_attr->masks.has_gid = 1;
        usr_attr->masks.has_ctime = 0;

        i=1;
        while(i<4) {

                cur_attr = usr_attr + i;
                cur_attr->path = NULL;
                cur_attr->mode = S_IRUSR|S_IRGRP|S_IROTH;
                cur_attr->size = 256;
                cur_attr->uid = 4711;
                cur_attr->gid = 2070;
                cur_attr->atime = 1234;
                cur_attr->mtime = time(NULL);

                i++;
        }

        LogDebug(COMPONENT_FSAL, "posix_setattrsv() for abcd1 called\n");

        posix_setattrsv(usr_attr, 4, FALSE);

        LogDebug(COMPONENT_FSAL, "posix_setattrsv() for abcd1 failed\n");

	free(usr_attr);


	/*
	 * get Attributes, ouput attributes in 'stat' format
	 */

	usr_attr = malloc(4 * sizeof(tc_attrs));
	memset(usr_attr, 0, sizeof(tc_attrs));
        usr_attr->path = "/home/garima/test/abcd";

        usr_attr->masks.has_mode = 1;
        usr_attr->masks.has_size = 1;
        usr_attr->masks.has_rdev = 1;
        usr_attr->masks.has_nlink = 1;
        usr_attr->masks.has_atime = 1;
        usr_attr->masks.has_mtime = 1;
        usr_attr->masks.has_uid = 1;
        usr_attr->masks.has_gid = 1;
        usr_attr->masks.has_ctime = 1;

	cur_attr = usr_attr + 1;
        cur_attr->path = "/home/garima/test/abcd1";
        cur_attr->masks.has_mode = 1;
        cur_attr->masks.has_size = 1;
        cur_attr->masks.has_rdev = 1;
        cur_attr->masks.has_nlink = 1;
        cur_attr->masks.has_atime = 1;
        cur_attr->masks.has_mtime = 1;
        cur_attr->masks.has_uid = 1;
        cur_attr->masks.has_gid = 1;
        cur_attr->masks.has_ctime = 1;

        i=2;
        while(i<4) {

                cur_attr = usr_attr + i;
                cur_attr->path = NULL;
                cur_attr->mode = S_IRUSR|S_IRGRP|S_IROTH;
                cur_attr->size = 256;
                cur_attr->uid = 4711;
                cur_attr->gid = 2070;
                cur_attr->atime = 1234;
                cur_attr->mtime = time(NULL);

                i++;
        }

        LogDebug(COMPONENT_FSAL, "posix_getattrsv() for abcd, abcd1 called\n");

        posix_getattrsv(usr_attr, 4, FALSE);

	char time[36];	
	LogDebug(COMPONENT_FSAL, " abcd : size %ld", usr_attr->size);
	LogDebug(COMPONENT_FSAL, " abcd : uid %d", usr_attr->uid);
	LogDebug(COMPONENT_FSAL, " abcd : gid %d", usr_attr->gid);
	LogDebug(COMPONENT_FSAL, " abcd : nlink %d", usr_attr->nlink);
	LogDebug(COMPONENT_FSAL, " abcd : rdev %ld", usr_attr->rdev);
	LogDebug(COMPONENT_FSAL, " abcd : atime %s", formattime(time, usr_attr->atime));
	LogDebug(COMPONENT_FSAL, " abcd : mtime %s", formattime(time, usr_attr->mtime));
	LogDebug(COMPONENT_FSAL, " abcd : ctime %s", formattime(time, usr_attr->ctime));

	char mode[11];
	memset(mode, '\0', 11);
	mode[0] = (S_ISDIR(usr_attr->mode)) ? 'd' : '-';
	mode[1] = (usr_attr->mode & S_IRUSR) ? 'r' : '-';
	mode[2] = (usr_attr->mode & S_IWUSR) ? 'w' : '-';
	mode[3] = (usr_attr->mode & S_IXUSR) ? 'x' : '-';
	mode[4] = (usr_attr->mode & S_IRGRP) ? 'r' : '-';
	mode[5] = (usr_attr->mode & S_IWGRP) ? 'w' : '-';
	mode[6] = (usr_attr->mode & S_IXGRP) ? 'x' : '-';
	mode[7] = (usr_attr->mode & S_IROTH) ? 'r' : '-';
	mode[8] = (usr_attr->mode & S_IWOTH) ? 'w' : '-';
	mode[9] = (usr_attr->mode & S_IXOTH) ? 'x' : '-';

	LogDebug(COMPONENT_FSAL, " abcd : mode %s\n", mode);
	
	cur_attr = usr_attr + 1;

	LogDebug(COMPONENT_FSAL, " abcd1 : size %ld", cur_attr->size);
	LogDebug(COMPONENT_FSAL, " abcd1 : uid %d", cur_attr->uid);
	LogDebug(COMPONENT_FSAL, " abcd1 : gid %d", cur_attr->gid);
	LogDebug(COMPONENT_FSAL, " abcd1 : nlink %d", cur_attr->nlink);
	LogDebug(COMPONENT_FSAL, " abcd1 : rdev %ld", cur_attr->rdev);
	LogDebug(COMPONENT_FSAL, " abcd1 : atime %s", formattime(time, cur_attr->atime));
	LogDebug(COMPONENT_FSAL, " abcd1 : mtime %s", formattime(time, cur_attr->mtime));
	LogDebug(COMPONENT_FSAL, " abcd1 : ctime %s", formattime(time, cur_attr->ctime));

	mode[0] = (S_ISDIR(cur_attr->mode)) ? 'd' : '-';
	mode[1] = (cur_attr->mode & S_IRUSR) ? 'r' : '-';
	mode[2] = (cur_attr->mode & S_IWUSR) ? 'w' : '-';
	mode[3] = (cur_attr->mode & S_IXUSR) ? 'x' : '-';
	mode[4] = (cur_attr->mode & S_IRGRP) ? 'r' : '-';
	mode[5] = (cur_attr->mode & S_IWGRP) ? 'w' : '-';
	mode[6] = (cur_attr->mode & S_IXGRP) ? 'x' : '-';
	mode[7] = (cur_attr->mode & S_IROTH) ? 'r' : '-';
	mode[8] = (cur_attr->mode & S_IWOTH) ? 'w' : '-';
	mode[9] = (cur_attr->mode & S_IXOTH) ? 'x' : '-';

	LogDebug(COMPONENT_FSAL, " abcd1 : mode %s\n", mode);
	
        LogDebug(COMPONENT_FSAL, "posix_getattrsv() for abcd, abcd1 successful\n");

	free(usr_attr);

        return 0;
}

