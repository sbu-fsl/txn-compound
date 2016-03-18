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
 * Helper function to populate tc_iovec for read/write
 */

tc_iovec* set_iovec(char **path, int count, int is_write)
{
	int i = 0;
	struct tc_iovec *user_arg = NULL;

	user_arg = calloc(count, sizeof(struct tc_iovec));

	while(i<count) {
		if(path[i] == NULL) {
			LogDebug(COMPONENT_FSAL, "set_iovec() failed for file : %s\n",
						  path[i]);

			int indx = 0;
			while(indx < i) {
				free((user_arg + indx)->data);
				indx++;
			}
			free(user_arg);

			return NULL;
		}

        	(user_arg + i)->path = path[i];
        	(user_arg + i)->offset = i * 7;
        	(user_arg + i)->length = 7;
        	(user_arg + i)->data = calloc(1, 8);

		if(is_write)
			strncpy((user_arg + i)->data, "abcd123", 7);
		
        	i++;
	}

	return user_arg;
}

/*
 * Test reads
 * @IN(path): array of files to be read
 * @IN(count): count of entries in the tc_iovec
 */

bool test_readv(char **path, int count, tc_iovec *check_arg)
{
	bool res = false;
	int i = 0;
        /*
         * posix_readv read the specified files
         */

	struct tc_iovec *user_arg = set_iovec(path, count, 0);
	if(user_arg == NULL)
		return res;
	
	res = tx_readv(user_arg, count);

	if(res && check_arg) {
		while(i <  count) {
			res = memcmp((void *)(user_arg + i)->data, (void *)(check_arg + i)->data, user_arg->length);

			if(res) {
				LogDebug(COMPONENT_FSAL, "Write failed\n");	
				break;
			}
			i++;
		}
	}

	i = 0;
	while(i < count) {
		free((user_arg + i)->data);
		i++;
	}

	free(user_arg);

	return res; 
}

/*
 * Test Writes
 * @IN(path): array of file to be written
 * @IN(count): count of entries in the tc_iovec
 */

bool test_writev(char **path, int count)
{
	bool res = false;

        /*
         * tx_writev write to the specified files
         */
       
	struct tc_iovec *user_arg = set_iovec(path, count, 1);
	if(user_arg == NULL)
		return res;
	
        res = tx_writev(user_arg, count);

	test_readv(path, count, user_arg); 

	clear_iovec(user_arg, count);

	return res;
}

/*
 * Compare the attributes once set, to check if set properly
 */

int compare(tc_attrs *usr, tc_attrs *check, int count)
{
	int i=0;
	while(i <  count) {

		LogDebug(COMPONENT_FSAL, "file name : %s", (usr + i)->path);

		if((usr + i)->masks.has_mode) {
			if(!((usr + i)->mode & (check + i)->mode)) {
				LogDebug(COMPONENT_FSAL, "Mode set op failed\n");
				LogDebug(COMPONENT_FSAL, " %d %d\n", (usr+i)->mode, (check + i)->mode);
				return -1;
			}
		}

		if((usr + i)->masks.has_rdev) {
			if(memcmp((void *)&((usr + i)->rdev), (void *)&((check + i)->rdev), sizeof((check + i)->rdev))) {
				LogDebug(COMPONENT_FSAL, "rdev set op failed\n");
				LogDebug(COMPONENT_FSAL, " %d %d\n", (usr+i)->rdev, (check + i)->rdev);
				return -1;
			}
		}

		if((usr + i)->masks.has_nlink) {
			if((usr + i)->nlink == (check + i)->nlink) {
				LogDebug(COMPONENT_FSAL, "nlink set op failed");
				LogDebug(COMPONENT_FSAL, " %d %d\n", (usr+i)->nlink, (check + i)->nlink);
				return -1;
			}
		}

		if((usr + i)->masks.has_uid) {
			if(memcmp((void *)&((usr + i)->uid),(void *) &((check + i)->uid), sizeof((check + i)->uid))) {
				LogDebug(COMPONENT_FSAL, "uid set op failed\n");
				LogDebug(COMPONENT_FSAL, " %d %d\n", (usr+i)->uid, (check + i)->uid);
				return -1;
			}
		}

		if((usr + i)->masks.has_gid) {
			if(memcmp((void *)&((usr + i)->gid), (void *)&((check + i)->gid), sizeof((check + i)->gid))) {
				LogDebug(COMPONENT_FSAL, "gid set op failed\n");
				LogDebug(COMPONENT_FSAL, " %d %d\n", (usr+i)->gid, (check + i)->gid);
				return -1;
			}
		}

		if((usr + i)->masks.has_atime) {
			if(memcmp((void *)&((usr + i)->atime), (void *)&((check + i)->atime), sizeof((check + i)->atime))) {
				LogDebug(COMPONENT_FSAL, "atime set op failed\n");
				LogDebug(COMPONENT_FSAL, " %d %d\n", (usr+i)->atime, (check + i)->atime);
				return -1;
			}
		}

		if((usr + i)->masks.has_mtime) {
			if(memcmp((void *)&((usr + i)->mtime), (void *)&((check + i)->mtime), sizeof((check + i)->mtime))) {
				LogDebug(COMPONENT_FSAL, "mtime failed\n");
				LogDebug(COMPONENT_FSAL, " %d %d\n", (usr+i)->mtime, (check + i)->mtime);
				return -1;
			}
		}

		i++;
	}
	return 0;
}

/*
 * Free the memory allocated to tc_attrs
 */

void clear_tc_attrsv(tc_attrs *attrs)
{
	free(attrs);
}

/*
 * Test the get attributes functionality
 */

bool test_getattrsv(char **path, int count, tc_attrs *check_attrs)
{
	tc_attrs *user_attr = calloc(count, sizeof(tc_attrs));
	tc_attrs_masks masks[3] = {0};	
        bool res = false;
	int err = 0, i = 0;

	while(i < count) {

		if(path[i] == NULL) {

			LogDebug(COMPONENT_FSAL, "test_getattrsv() failed for file : %s\n", path[i]);

			free(user_attr);
			return res;
		}

		masks[i].has_mode = 1;
                masks[i].has_size = 1;
                masks[i].has_atime = 1;
                masks[i].has_mtime = 1;
                masks[i].has_uid = 1;
                masks[i].has_gid = 1;
                masks[i].has_rdev = 0;
                masks[i].has_nlink = 0;
                masks[i].has_ctime = 0;

		(user_attr + i)->path = path[i];
		(user_attr + i)->masks = masks[i];

		i++;
	}

        res = tx_getattrsv(user_attr, count);

	if(check_attrs  && res) {
		err = compare(user_attr, check_attrs, count);

		if(err) {
			res = false;
			LogDebug(COMPONENT_FSAL, "Attributes did not set successfully\n");
		}
	}
			
        clear_tc_attrsv(user_attr);

	return res;
}

/*
 * Test set attribute functionality
 * @IN(path): array of files whose attributes are to be set
 * @IN(count): count of entries in the tc_attrs
 * @IN(masks): bit fields indicating which field needs modification
 */

bool test_setattrsv(char **path, tc_attrs *change_attr, int count)
{
	tc_attrs *user_attr = change_attr;
	bool res = false;

	res = tx_setattrsv(user_attr, count);
	
	if(res) {
		res = test_getattrsv(path, count, user_attr);
		if(!res)
			LogDebug(COMPONENT_FSAL, "tc_getattr() failed \n");	
			
	}

	return res;
}

/*
 * helper function to populate tc_attrs struct
 * @IN(path): array of files whose attributes are to be set
 * @IN(count): count of entries in the tc_attrs
 */
tc_attrs* set_tc_attrs(char **path, int count)
{
	tc_attrs *change_attr = calloc(count, sizeof(tc_attrs));
	tc_attrs_masks masks[3] = {0};
	int i = 0;

	uid_t uid[] = {2711, 456, 789};
	gid_t gid[] = {87, 4566, 2311};
	mode_t mode[] = {S_IRUSR|S_IRGRP|S_IROTH, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH, S_IRWXU};
	size_t size[] = {256, 56, 125};
	time_t atime[] = {time(NULL), 1234, 567};
	

	while(i < count) {

		if(path[i] == NULL) {

                        LogDebug(COMPONENT_FSAL, "set_tc_attrs() failed for file : %s\n", path[i]);

                        free(change_attr);
                        return NULL;
                }

		(change_attr + i)->path = path[i];	
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

/*
 * Test cases for read/write and getattr/setattr methods
 * All the test cases are placed in this function
 */

int test()
{
	
	bool res = true;
	tc_attrs *change_attr = NULL;

	char *file_name[] = {"/home/garima/test/abcd", "/home/garima/test/abcd", "/home/garima/test/abcd1", NULL};

	/*************************************************************
         ***************** Read Test cases ***************************
         *************************************************************
         */
        
	res = test_readv(file_name, 3, NULL);

	if(res)
		LogDebug(COMPONENT_FSAL, "tc_readv() successful\n");


	/*
	 * posix_readv should fail with file not found error
	 */
        res = test_readv(file_name, 4, NULL);

	if(res)
                LogDebug(COMPONENT_FSAL, "tc_readv() successful\n");	

	
	/*************************************************************
         ***************** Write Test cases ***************************
         *************************************************************
         */

	/*
	 * Test Sequential writes to the same file
	 */
        res = test_writev(file_name, 3);

	if(res)
        	LogDebug(COMPONENT_FSAL, "tc_writev() successful\n");

	/*
	 * tc_writev failed, File not found error
	 */

        res = test_writev(file_name, 4);

	if(res)
                LogDebug(COMPONENT_FSAL, "tc_writev() successful\n");


	/*************************************************************
	 ***************** Attributes ********************************
	 *************************************************************
	 */

	/* Set the masks which will be needed for multiple test cases */
	char *attr_files[] = {"/home/garima/test/abcd2", "/home/garima/test/abcd1", "/home/garima/test/abcd"};
	change_attr = set_tc_attrs(attr_files, 3);


	/*
	 * SetAttributes test should pass
	 * (all the fields are properly set)
         */
	if(change_attr) {
        	res = test_setattrsv(attr_files, change_attr, 3);

		if(res)
        		LogDebug(COMPONENT_FSAL, "tc_setattrsv() successful\n");
	}
		

	/*
	 * Set Attributes fail, since rdev is set 
	 */

	(change_attr + 1)->masks.has_rdev = 1;
        res = test_setattrsv(attr_files, change_attr, 3);

	if(res)
        	LogDebug(COMPONENT_FSAL, "tc_setattrsv() successful\n");


	clear_tc_attrsv(change_attr);

        return 0;
}

