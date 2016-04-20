/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright Stony Brook University, 2014
 * Ming Chen <mchen@cs.stonybrook.edu>
 *
 * Copyright CEA/DAM/DIF  (2008)
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * ---------------------------------------
 */

/**
 * @file    nfs4_op_read.c
 * @brief   NFSv4 read operation
 *
 * This file implements NFS4_OP_READ_PLUS within an NFSv4 compound call.
 */
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "hashtable.h"
#include "log.h"
#include "ganesha_rpc.h"
#include "nfs4.h"
#include "nfs_core.h"
#include "sal_functions.h"
#include "nfs_proto_functions.h"
#include "nfs_proto_tools.h"
#include <stdlib.h>
#include <unistd.h>
#include "export_mgr.h"
#include "nfs_convert.h"
#include "fsal_pnfs.h"
#include "server_stats.h"
#include "nfs_integrity.h"

#define ALIGNMENT 4096

void get_protection_type4(nfs_protection_info4 *pi)
{
	memset(pi, 0, sizeof(*pi));

	if (op_ctx->export != NULL) {
		/* TODO read from export configuration file:
		 * pi->pi_type = op_ctx->export->dix_protection_type;*/
		pi->pi_type = 5;
		/*
		 * This means 4K is our smallest I/O size.
		 * TODO ideally we should read from config file
		 */
		pi->pi_intvl_size = PI_INTERVAL_SIZE;
		pi->pi_other_data = 0;
	}

	if (pi->pi_type != 5) {
		/* Now, only type 5 is supported, disable PI if not type 5 */
		pi->pi_type = NFS_PI_NOT_SUPPORTED;
	}
}

static int fill_data4(data4 *d, off_t offset, size_t size)
{
	/*data4 *d = &rpc->read_plus_content4_u.rpc_data;*/
	void *data = NULL;

	if (size > 0 && !(data = gsh_malloc_aligned(ALIGNMENT, size)))
		return NFS4ERR_SERVERFAULT;


	d->d_offset = offset;
	d->d_allocated = true;
	d->d_data.data_len = size;
	d->d_data.data_val = data;

	return NFS4_OK;
}

static inline void clean_data4(data4 *d)
{
	gsh_free(d->d_data.data_val);
}

static int fill_data_protected(data_protected4 *pd, off_t offset, size_t size,
			       nfs_protection_info4 *pi)
{
	/*data_protected4 *pd = &rpc4->read_plus_content4_u.rpc_pdata;*/
	void *data = NULL;
	void *pi_data = NULL;
	size_t pi_size = 0;

	if (size > 0) {
		if (!(data = gsh_malloc_aligned(ALIGNMENT, size)))
			return NFS4ERR_SERVERFAULT;
		pi_size = get_pi_size(size);
		if (!(pi_data = gsh_malloc_aligned(ALIGNMENT, pi_size))) {
			gsh_free(data);
			return NFS4ERR_SERVERFAULT;
		}
	}

	pd->pd_type = *pi;
	pd->pd_offset = offset;
	pd->pd_allocated = true;
	pd->pd_data.pd_data_len = size;
	pd->pd_data.pd_data_val = data;
	pd->pd_info.pd_info_len = pi_size;
	pd->pd_info.pd_info_val = pi_data;

	return NFS4_OK;
}

static inline void clean_data_protected4(data_protected4 *pd)
{
	gsh_free(pd->pd_data.pd_data_val);
	gsh_free(pd->pd_info.pd_info_val);
}

static int fill_protect_info4(data_protect_info4 *dpi, off_t offset,
			      size_t size, nfs_protection_info4 *pi)
{
	void *pi_data = NULL;
	size_t pi_size = 0;

	pi_size = get_pi_size(size);
	if (pi_size > 0 && !(pi_data = gsh_malloc_aligned(ALIGNMENT, pi_size)))
		return NFS4ERR_SERVERFAULT;

	dpi->pi_type = *pi;
	dpi->pi_offset = offset;
	dpi->pi_allocated = true;
	dpi->pi_data.pi_data_len = pi_size;
	dpi->pi_data.pi_data_val = pi_data;

	return NFS4_OK;
}

static inline void clean_protect_info4(data_protect_info4 *dpi)
{
	gsh_free(dpi->pi_data.pi_data_val);
}

/* fill contents and allocate space */
static int fill_contents(contents *io_content, off_t offset, size_t size,
			 data_content4 content_type, nfs_protection_info4 *pi)
{
	int ret = NFS4_OK;

	memset(io_content, 0, sizeof(*io_content));

	switch (content_type) {
	case NFS4_CONTENT_DATA:
		ret = fill_data4(&io_content->data, offset, size);
		break;
	case NFS4_CONTENT_PROTECTED_DATA:
		ret = fill_data_protected(&io_content->pdata, offset, size, pi);
		break;
	case NFS4_CONTENT_PROTECT_INFO:
		ret = fill_protect_info4(&io_content->pinfo, offset, size, pi);
		break;
	case NFS4_CONTENT_APP_DATA_HOLE:
	case NFS4_CONTENT_HOLE:
	default:
		ret = NFS4ERR_NOTSUPP;
		LogMajor(COMPONENT_NFS_V4, "BUG: operations not supported "
					   "should not reach here.");
	}

	io_content->what = content_type;

	return ret;
}

static void clean_contents(contents *io_content)
{
	switch (io_content->what) {
	case NFS4_CONTENT_DATA:
		clean_data4(&io_content->data);
		break;
	case NFS4_CONTENT_PROTECTED_DATA:
		clean_data_protected4(&io_content->pdata);
		break;
	case NFS4_CONTENT_PROTECT_INFO:
		clean_protect_info4(&io_content->pinfo);
		break;
	case NFS4_CONTENT_APP_DATA_HOLE:
	case NFS4_CONTENT_HOLE:
	default:
		LogMajor(COMPONENT_NFS_V4, "BUG: operations not supported "
			 "should not reach here.");
	}
}

/* set how many bytes have been read correctly in "contents" */
static void set_content_size(size_t bytes_read, contents* cont)
{
	switch (cont->what) {
	case NFS4_CONTENT_DATA:
		cont->data.d_data.data_len = bytes_read;
		break;
	case NFS4_CONTENT_PROTECTED_DATA:
		cont->pdata.pd_data.pd_data_len = bytes_read;
		cont->pdata.pd_info.pd_info_len = get_pi_size(bytes_read);
		break;
	case NFS4_CONTENT_PROTECT_INFO:
		cont->pinfo.pi_data.pi_data_len = get_pi_size(bytes_read);
		break;
	default:
		LogMajor(COMPONENT_NFS_V4, "BUG: operations not supported: %d",
			 cont->what);
	}
}

static int fill_read_plus_res(READ_PLUS4res *rp4res, size_t bytes_read,
			      const contents *io_content, bool eof)
{
	contents* cont = NULL;

	rp4res->rpr_resok4.rpr_eof = eof;
	rp4res->rpr_resok4.rpr_contents_len = (bytes_read > 0) ? 1 : 0;

	if (bytes_read > 0) {
		/* This newly allocated "contents" will be released at the last
		 * step of nfs4_op_read_plus_Free(). */
		cont = gsh_malloc(sizeof(contents));
		if (cont == NULL) {
			rp4res->rpr_status = NFS4ERR_SERVERFAULT;
		} else {
			/* ownership of data buffer(s) will be passed from
			 * "io_content" to "cont' */
			memcpy(cont, io_content, sizeof(contents));
			set_content_size(bytes_read, cont);
			rp4res->rpr_status = NFS4_OK;
		}
	} else {
		assert(io_content == NULL);
		rp4res->rpr_status = NFS4_OK;
	}

	rp4res->rpr_resok4.rpr_contents_val = cont;

	return rp4res->rpr_status;
}

static int op_dsread_plus(struct nfs_argop4 *op, compound_data_t *data,
			  struct nfs_resop4 *resp, struct io_info *info)
{
	READ4args * const arg_READ4 = &op->nfs_argop4_u.opread;
	READ_PLUS4res * const res_RPLUS = &resp->nfs_resop4_u.opread_plus;
	contents *contentp = res_RPLUS->rpr_resok4.rpr_contents_val;
	/* NFSv4 return code */
	nfsstat4 nfs_status = 0;
	/* Buffer into which data is to be read */
	void *buffer = NULL;
	/* End of file flag */
	bool eof = false;

	/* Don't bother calling the FSAL if the read length is 0. */

	if (arg_READ4->count == 0) {
		res_RPLUS->rpr_resok4.rpr_contents_len = 1;
		res_RPLUS->rpr_resok4.rpr_eof = FALSE;
		contentp->what = NFS4_CONTENT_DATA;
		contentp->data.d_offset = arg_READ4->offset;
		contentp->data.d_allocated = FALSE;
		contentp->data.d_data.data_len =  0;
		contentp->data.d_data.data_val = NULL;
		res_RPLUS->rpr_status = NFS4_OK;
		return res_RPLUS->rpr_status;
	}

	/* Construct the FSAL file handle */

	buffer = gsh_malloc_aligned(4096, arg_READ4->count);
	if (buffer == NULL) {
		LogEvent(COMPONENT_NFS_V4, "FAILED to allocate read buffer");
		res_RPLUS->rpr_status = NFS4ERR_SERVERFAULT;
		return res_RPLUS->rpr_status;
	}

	nfs_status = data->current_ds->ops->read_plus(
				data->current_ds,
				op_ctx,
				&arg_READ4->stateid,
				arg_READ4->offset,
				arg_READ4->count,
				buffer,
				arg_READ4->count,
				&eof, info);

	res_RPLUS->rpr_status = nfs_status;
	if (nfs_status != NFS4_OK) {
		gsh_free(buffer);
		return res_RPLUS->rpr_status;
	}

	contentp->what = info->io_content.what;
	res_RPLUS->rpr_resok4.rpr_contents_len = 1;
	res_RPLUS->rpr_resok4.rpr_eof = eof;

	if (info->io_content.what == NFS4_CONTENT_HOLE) {
		contentp->hole.di_offset = info->io_content.hole.di_offset;
		contentp->hole.di_length = info->io_content.hole.di_length;
		contentp->hole.di_allocated =
					info->io_content.hole.di_allocated;
	}
	if (info->io_content.what == NFS4_CONTENT_DATA) {
		contentp->data.d_offset = info->io_content.data.d_offset;
		contentp->data.d_allocated = info->io_content.data.d_allocated;
		contentp->data.d_data.data_len =
					info->io_content.data.d_data.data_len;
		contentp->data.d_data.data_val =
					info->io_content.data.d_data.data_val;
	}
	return res_RPLUS->rpr_status;
}

int nfs4_op_read_plus(struct nfs_argop4 *op, compound_data_t *compound,
		      struct nfs_resop4 *resp)
{
	READ_PLUS4args * const rp4args = &op->nfs_argop4_u.opread_plus;
	READ_PLUS4res * const rp4res = &resp->nfs_resop4_u.opread_plus;
	uint64_t size = 0;
	size_t read_size = 0;
	uint64_t offset = 0;
	bool eof_met = false;
	void *bufferdata = NULL;
	cache_inode_status_t cache_status = CACHE_INODE_SUCCESS;
	state_t *state_found = NULL;
	state_t *state_open = NULL;
	uint64_t file_size = 0;
	cache_entry_t *entry = NULL;
	bool sync = false;
	/* This flag is set to true in the case of an anonymous read
	 * so that we know to release the state lock afterward.  The
	 * state lock does not need to be held during a non-anonymous
	 * read, since the open state itself prevents a conflict.
	 */
	bool anonymous = false;
	struct io_info info = {0};
	nfs_protection_info4 pi;

	info.io_content.what = rp4args->rpa_content;
	if (rp4args->rpa_content == NFS4_CONTENT_APP_DATA_HOLE ||
	    rp4args->rpa_content == NFS4_CONTENT_HOLE) {
		rp4res->rpr_status = NFS4ERR_NOTSUPP;
		return rp4res->rpr_status;
	}

	resp->resop = NFS4_OP_READ_PLUS;
	memset(rp4res, 0, sizeof(*rp4res));
	rp4res->rpr_status = NFS4_OK;

	if ((compound->minorversion > 0) &&
	    nfs4_Is_Fh_DSHandle(&compound->currentFH))
		return op_dsread_plus(op, compound, resp, &info);

	/* Do basic checks on a filehandle Only files can be read */
	rp4res->rpr_status = nfs4_sanity_check_FH(compound, REGULAR_FILE, true);
	if (rp4res->rpr_status != NFS4_OK)
		return rp4res->rpr_status;

	entry = compound->current_entry;

	/* Check stateid correctness and get pointer to state (also checks for
	 * special stateids) */
	rp4res->rpr_status = nfs4_Check_Stateid(
	    &rp4args->rpa_stateid, entry, &state_found, compound,
	    STATEID_SPECIAL_ANY, 0, false, "READ_PLUS4");
	if (rp4res->rpr_status != NFS4_OK)
		return rp4res->rpr_status;

	/* NB: After this point, if state_found == NULL, then the
	 * stateid is all-0 or all-1
	 */
	if (state_found != NULL) {
		info.io_advise = state_found->state_data.io_advise;
		switch (state_found->state_type) {
		case STATE_TYPE_SHARE:
			state_open = state_found;
			/**
			 * @todo FSF: need to check against existing locks
			 */
			break;

		case STATE_TYPE_LOCK:
			state_open = state_found->state_data.lock.openstate;
			/**
			 * @todo FSF: should check that write is in
			 * range of an byte range lock...
			 */
			break;

		case STATE_TYPE_DELEG:
			state_open = NULL;
			/**
			 * @todo FSF: should check that this is a read
			 * delegation?
			 */
			break;

		default:
			rp4res->rpr_status = NFS4ERR_BAD_STATEID;
			LogDebug(COMPONENT_NFS_V4_LOCK,
				 "READ_PLUS with invalid statid of type %d",
				 state_found->state_type);
			return rp4res->rpr_status;
		}

		/* This is a read operation, this means that the file
		 * MUST have been opened for reading
		 */
		if (state_open != NULL
		    && (state_open->state_data.share.
			share_access & OPEN4_SHARE_ACCESS_READ) == 0) {
			/* Even if file is open for write, the client
			 * may do accidently read operation (caching).
			 * Because of this, READ is allowed if not
			 * explicitely denied.  See page 72 in RFC3530
			 * for more details
			 */
			if (state_open->state_data.share.
			    share_deny & OPEN4_SHARE_DENY_READ) {
				/* Bad open mode, return NFS4ERR_OPENMODE */
				rp4res->rpr_status = NFS4ERR_OPENMODE;
				LogDebug(COMPONENT_NFS_V4_LOCK,
					 "READ_PLUS state %p doesn't have "
					 "OPEN4_SHARE_ACCESS_READ",
					 state_found);
				return rp4res->rpr_status;
			}
		}

		/**
		 * @todo : this piece of code looks a bit suspicious
		 *  (see Rong's mail)
		 *
		 * @todo: ACE: This works for now.  How do we want to
		 * handle owner confirmation across NFSv4.0/NFSv4.1?
		 * Do we want to mark every NFSv4.1 owner
		 * pre-confirmed, or make the check conditional on
		 * minorversion like we do here?
		 */
		switch (state_found->state_type) {
		case STATE_TYPE_SHARE:
			if ((compound->minorversion == 0) &&
			    (!state_found->state_owner->so_owner.so_nfs4_owner.
			       so_confirmed)) {
				rp4res->rpr_status = NFS4ERR_BAD_STATEID;
				return rp4res->rpr_status;
			}
			break;

		case STATE_TYPE_LOCK:
			/* Nothing to do */
			break;

		default:
			/* Sanity check: all other types are illegal.
			 * we should not got that place (similar check
			 * above), anyway it costs nothing to add this
			 * test
			 */
			rp4res->rpr_status = NFS4ERR_BAD_STATEID;
			return rp4res->rpr_status;
		}
	} else {
		/* Special stateid, no open state, check to see if any
		 * share conflicts
		 */
		state_open = NULL;
		PTHREAD_RWLOCK_rdlock(&entry->state_lock);
		anonymous = true;

		/* Special stateid, no open state, check to see if any share
		 * conflicts The stateid is all-0 or all-1
		 */
		rp4res->rpr_status = nfs4_check_special_stateid(
		    entry, "READ_PLUS4", FATTR4_ATTR_READ);
		if (rp4res->rpr_status != NFS4_OK) {
			PTHREAD_RWLOCK_unlock(&entry->state_lock);
			return rp4res->rpr_status;
		}
	}

	if (state_open == NULL &&
	    entry->obj_handle->attributes.owner != op_ctx->creds->caller_uid) {
		/* Need to permission check the read. */
		cache_status = cache_inode_access(entry, FSAL_READ_ACCESS);

		if (cache_status == CACHE_INODE_FSAL_EACCESS) {
			/* Test for execute permission */
			cache_status = cache_inode_access(
				entry,
				FSAL_MODE_MASK_SET(FSAL_X_OK) |
				FSAL_ACE4_MASK_SET(FSAL_ACE_PERM_EXECUTE));
		}

		if (cache_status != CACHE_INODE_SUCCESS) {
			rp4res->rpr_status = nfs4_Errno(cache_status);
			goto done;
		}
	}

	offset = rp4args->rpa_offset;
	size = rp4args->rpa_count;

	if (op_ctx->export->MaxOffsetRead < UINT64_MAX) {
		LogFullDebug(COMPONENT_NFS_V4,
			     "Read offset=%" PRIu64 " count=%zd "
			     "MaxOffSet=%" PRIu64, offset, size,
			     op_ctx->export->MaxOffsetRead);

		if ((offset + size) > op_ctx->export->MaxOffsetRead) {
			LogEvent(COMPONENT_NFS_V4,
				 "A client tryed to violate max "
				 "file size %" PRIu64 " for exportid #%hu",
				 op_ctx->export->MaxOffsetRead,
				 op_ctx->export->export_id);
			rp4res->rpr_status = NFS4ERR_DQUOT;
			goto done;
		}
	}

	if (size > op_ctx->export->MaxRead) {
		/* the client asked for too much data, this should normally
		   not happen because client will get FATTR4_MAXREAD value
		   at mount time */

		if (info.io_content.what != NFS4_CONTENT_HOLE) {
			LogFullDebug(COMPONENT_NFS_V4,
				     "read requested size = %"PRIu64
				     " read allowed size = %" PRIu64,
				     size, op_ctx->export->MaxRead);
			size = op_ctx->export->MaxRead;
		}
	}

	/* If size == 0, no I/O is to be made and everything is alright */
	if (size == 0) {
		/* A size = 0 can not lead to EOF */
		fill_read_plus_res(rp4res, 0, NULL, false);
		goto done;
	}

	get_protection_type4(&pi);
	rp4res->rpr_status = fill_contents(&info.io_content, offset, size,
					   rp4args->rpa_content, &pi);
	if (rp4res->rpr_status != NFS4_OK) {
		goto done;
	}

	if (!anonymous && compound->minorversion == 0) {
		op_ctx->clientid =
		    &state_found->state_owner->so_owner.so_nfs4_owner.
		    so_clientid;
	}

	cache_status = cache_inode_rdwr_plus(entry, CACHE_INODE_READ_PLUS,
					     offset, size, &read_size,
					     bufferdata, &eof_met,
					     &sync, &info);

	if (cache_status != CACHE_INODE_SUCCESS) {
		rp4res->rpr_status = nfs4_Errno(cache_status);
		clean_contents(&info.io_content);
		goto done;
	}

	if (cache_inode_size(entry, &file_size) != CACHE_INODE_SUCCESS) {
		rp4res->rpr_status = nfs4_Errno(cache_status);
		clean_contents(&info.io_content);
		goto done;
	}

	if (!anonymous && compound->minorversion == 0)
		op_ctx->clientid = NULL;

	LogFullDebug(COMPONENT_NFS_V4,
		     "NFS4_OP_READ_PLUS: offset = %" PRIu64
		     " read length = %zu eof=%u",
		     offset, read_size, eof_met);

	eof_met = eof_met || ((offset + read_size) >= file_size);
	fill_read_plus_res(rp4res, read_size, &info.io_content, eof_met);

done:
	if (anonymous)
		PTHREAD_RWLOCK_unlock(&entry->state_lock);

#ifdef USE_DBUS_STATS
	server_stats_io_done(size, read_size, rp4res->rpr_status == NFS4_OK,
			     false);
#endif

	return rp4res->rpr_status;
}				/* nfs4_op_read_plus */

/**
 * @brief Free data allocated for READ_PLUS result.
 *
 * This function frees any data allocated for the result of the
 * NFS4_OP_READ_PLUS operation.
 *
 * @param[in,out] resp  Results fo nfs4_op
 *
 */
void nfs4_op_read_plus_Free(nfs_resop4 *res)
{
	READ_PLUS4res * const rp4res = &res->nfs_resop4_u.opread_plus;
	read_plus_res4 *rpr4 = &rp4res->rpr_resok4;
	int rpc_len = rpr4->rpr_contents_len;
	contents *rpc4s = rpr4->rpr_contents_val;
	int i;

	for (i = 0; i < rpc_len; ++i) {
		clean_contents(rpc4s + i);
	}

	gsh_free(rpc4s);
}				/* nfs4_op_read_plus_Free */
