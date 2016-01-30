#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

char usage[] = "tc_test Help\n"
	       "============\n\n"	
	       "Usage example:\n"
	       "./tc_test -b 2048 -n 50 -m 20 -c 5 -p \"/mnt/test/abcd\" -r \n"
	       "-b <Block_size per read/write>\n"
	       "-l <Path of the input files>\n"
	       "-n <Num of files of the form path0, path1, path2, ....>\n"
	       "-m <Num of reads/writes per file>\n"
	       "-c <Num of reads/writes per compound>\n"
	       "-r <Read>\n"
	       "-w <Write>\n"
	       "Only one of -r,-w can be specifed\n";

int main(int argc, char *argv[])
{
	FILE *fp;
	char *temp_path = NULL;
	char *input_path = NULL;
	int input_len = 0;
	char *data_buf = NULL;
	int block_size = 0; /* int because the max block size is 16k */
	int num_files = 0;
	int ops_per_comp = 0;
	int num_ops = 0;
	int rw = 0;
	int i = 0;
	int j = 0;
	int opt;
	clock_t t;
	double time_taken;

	while ((opt = getopt(argc, argv, "b:n:m:c:p:hrw")) != -1) {
		switch (opt) {
		case 'b':
			/* Block size per read/write */

			block_size = atoi((char *)optarg);

			if (block_size <= 0 || block_size > 20 * 1024) {
				printf(
				    "Invalid block size or it exceeds 20k\n");
				exit(-1);
			}

			break;
		case 'n':
			/*
			 * Total number of files, each file of the form
			 * /mnt/test/abcd0, /mnt/test/abcd1, .....
			 * if the path is specified as "/mnt/test/abcd"
			 */

			num_files = atoi((char *)optarg);

			if (num_files <= 0 || num_files > 200) {
				printf(
				    "Number of files exceeds 200 or invalid\n");
				exit(-1);
			}

			break;
		case 'm':
			/*
			 * Total number of reads/writes per file, an alternative
			 * to file size
			 */

			num_ops = atoi((char *)optarg);

			if (num_ops <= 0 || num_ops > 30) {
				printf("Invalid total number of reads/writes "
				       "or it exceeds 30\n");
				exit(-1);
			}

			break;
		case 'c':
			/*
			 * Number of operations in a single compound, should not
			 * matter in normal reads
			 */

			ops_per_comp = atoi((char *)optarg);

			if (ops_per_comp <= 0 || ops_per_comp > 10) {
				printf(
				    "Invalid ops per comp or it exceeds 10\n");
				exit(-1);
			}

			break;
		case 'l':
			/*
			 * Path of the files
			 *
			 * If the files are of the form -
			 * /mnt/test/abcd0, /mnt/test/abcd1, ......
			 * Path should be "/mnt/test/abcd"
			 */

			input_path = (char *)optarg;
			input_len = strlen(input_path);
			if (input_len <= 0 || input_len > 50) {
				printf("Name is invalid or is too long, max 50 chars \n");
				exit(-1);
			}

			break;
		case 'r':
			/* Read */

			rw = 0;

			break;
		case 'w':
			/* Write */

			rw = 1;

			break;
		case 'h':
		default:
			printf("%s", usage);
			exit(-1);
		}
	}

	if (argc != 12) {
		printf("Wrong usage, use -h to get help\n");
		exit(-1);
	}

	if (rw == 0) {
		printf("TC_TEST - READ\n");
	} else {
		printf("TC_TEST - WRITE\n");
	}
	printf("Block size - %d\n", block_size);
	printf("Path - %s\n", input_path);
	printf("Num_files - %d\n", num_files);
	printf("Num of reads/writes per file - %d\n", num_ops);
	printf("Num of ops in a comp - %d\n", ops_per_comp);

	temp_path = malloc(input_len + 4); /* 4 because the num_files <= 200 */
	data_buf = malloc(block_size);
	j = 0;
	t = clock();
	while (j < num_files) {

		snprintf(temp_path, input_len + 4, "%s%d", input_path, j);

		if (rw == 0) { /* Read */
			fp = fopen(temp_path, "r");
		} else { /* Write */
			fp = fopen(temp_path, "w");
		}

		if (fp == NULL) {
			printf("Error opening file - %s\n", temp_path);
			goto exit;
		}

		i = 0;
                while (i < num_ops) {
			if (rw == 0) { /* Read */
				fread(data_buf, block_size, 1, (FILE *)fp);
			} else { /* Write */
				fwrite(data_buf, 1, block_size, (FILE *)fp);
			}
                        i++;
                }

                fclose(fp);
                j++;
        }

	t = clock() - t;
	// time_taken = ((double)t) / CLOCKS_PER_SEC;
	time_taken = ((double)t);

	printf("Took %f seconds to execute \n", time_taken);

exit:
	free(data_buf);
        free(temp_path);

	return 0;
}
