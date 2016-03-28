#include "config.h"
#include <ctype.h>
#include <string.h>
#include <netdb.h>
#include <math.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "fsal_types.h"
#include "fsal_api.h"
#include "fsal.h"
#include "FSAL/fsal_init.h"
#include "fs_fsal_methods.h"
#include "tc_utils.h"
#include <time.h>

double randn(double mu, double sigma)
{
	double U1, U2, W, mult;
	static double X1, X2;
	static int call = 0;

	if (call == 1) {
		call = !call;
		return (mu + sigma * (double)X2);
	}

	do {
		U1 = -1 + ((double)rand() / RAND_MAX) * 2;
		U2 = -1 + ((double)rand() / RAND_MAX) * 2;
		W = pow(U1, 2) + pow(U2, 2);
	} while (W >= 1 || W == 0);

	mult = sqrt((-2 * log(W)) / W);
	X1 = U1 * mult;
	X2 = U2 * mult;

	call = !call;

	return (mu + sigma * (double)X1);
}

int tc_test(char *input_path, unsigned int block_size, unsigned int num_files,
	    int num_ops, int ops_per_comp, int rw)
{
	struct fsal_module *new_module = NULL;
	struct gsh_export *export = NULL;
	struct fsal_obj_handle *vfs0_handle = NULL;
	fsal_status_t fsal_status = { 0, 0 };
	struct req_op_context req_ctx;
	struct tc_iovec *user_arg = NULL;
	struct tc_iovec *cur_arg = NULL;
	char *temp_path = NULL;
	char *data_buf = NULL;
	unsigned int *op_array = NULL;
        unsigned int *temp_array = NULL;
	int input_len = 0;
	int i = 0;
	int j = 0;
	int k = 0;
	clock_t t;
	float time_taken;
	struct timeval tv1, tv2;

	srand(time(NULL));

	LogDebug(COMPONENT_FSAL, "test2() called\n");
	new_module = lookup_fsal("PROXY");
	if (new_module == NULL) {
		LogDebug(COMPONENT_FSAL, "Proxy Module Not found\n");
		return -1;
	}
	LogDebug(COMPONENT_FSAL, "Proxy Module Found\n");
	export = get_gsh_export(77);
	if(export == NULL){
		LogDebug(COMPONENT_FSAL, "Export Not found\n");
		return -1;
	}
	LogDebug(COMPONENT_FSAL, "Export Found\n");
	LogDebug(COMPONENT_FSAL,
                 "Export %d at pseudo (%s) with path (%s) and tag (%s) \n",
                 export->export_id, export->pseudopath,
                 export->fullpath, export->FS_tag);

	
	sleep(1);

	memset(&req_ctx, 0, sizeof(struct req_op_context));
	op_ctx = &req_ctx;
	op_ctx->creds = NULL;
	op_ctx->export = export;
	op_ctx->fsal_export = export->fsal_export;

	input_len = strlen(input_path);
	temp_path = malloc(input_len + 4);

	user_arg = malloc(ops_per_comp * (sizeof(struct tc_iovec)));
	k = 0;
	while (k < ops_per_comp) {
		cur_arg = user_arg + k;
		cur_arg->data = malloc(block_size);
		k++;
	}

	k=0;
	op_array = malloc(num_ops * sizeof(unsigned int));
	while (k < num_ops) {
		temp_array = op_array + k;
		*temp_array = randn(num_ops / 2, num_ops / 8);
		k++;
	}

	//t = clock();
	gettimeofday(&tv1, NULL);

	while (j < num_ops) {

		k = 0;
		while (k < ops_per_comp) {
			cur_arg = user_arg + k;
			temp_array = op_array + j + k;
			snprintf(temp_path, input_len + 8, "%s%d",
				 input_path, *temp_array);
			cur_arg->file = tc_file_from_path(temp_path);
			cur_arg->offset = 0;
			cur_arg->length = block_size;
			k++;
		}

		if (rw == 0) {
			tcread_v(user_arg, ops_per_comp, FALSE);
		} else {
			tcwrite_v(user_arg, ops_per_comp, FALSE);
		}
		j = j + ops_per_comp;
	}

	//t = clock() - t;
	//time_taken = ((double)t)/CLOCKS_PER_SEC;
	//time_taken = (float) t;
	gettimeofday(&tv2, NULL);
	time_taken = ((double)(tv2.tv_usec - tv1.tv_usec) / 1000000) +
		     (double)(tv2.tv_sec - tv1.tv_sec);
	LogFatal(COMPONENT_FSAL, "tcreads done - %f seconds\n", time_taken);

	i = 0;
	while (i < 100) {
		cur_arg = user_arg + i;
		free(cur_arg->data);
		i++;
	}

	free(user_arg);
	free(temp_path);
	return 0;
}
