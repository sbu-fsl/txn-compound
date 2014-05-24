/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright CEA/DAM/DIF  (2008)
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *
 * Copyright Stony Brook University, 2014
 * Ming Chen <v.mingchen@gmail.com>
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
#include "fsal_pnfs.h"
#include "server_stats.h"
#include "nfs_integrity.h"

#define ALIGNMENT 4096

#define rpc_data_data_len(rpc4) \
	rpc4->read_plus_content4_u.rpc_data.d_data.d_data_len

#define rpc_data_data_val(rpc4) \
	rpc4->read_plus_content4_u.rpc_data.d_data.d_data_val

#define rpc_pdata_data_len(rpc4) \
	rpc4->read_plus_content4_u.rpc_pdata.pd_data.pd_data_len

#define rpc_pdata_data_val(rpc4) \
	rpc4->read_plus_content4_u.rpc_pdata.pd_data.pd_data_val

#define rpc_pdata_info_len(rpc4) \
	rpc4->read_plus_content4_u.rpc_pdata.pd_info.pd_info_len

#define rpc_pdata_info_val(rpc4) \
	rpc4->read_plus_content4_u.rpc_pdata.pd_info.pd_info_val

#define rpc_pinfo_data_len(rpc4) \
	rpc4->read_plus_content4_u.rpc_pinfo.pi_data.pi_data_len

#define rpc_pinfo_data_val(rpc4) \
	rpc4->read_plus_content4_u.rpc_pinfo.pi_data.pi_data_val


void get_protection_type4(compound_data_t *compound, nfs_protection_info4 *pi)
{
	memset(pi, 0, sizeof(*pi));

	if (compound != NULL && compound->export != NULL) {
		pi->pi_type = compound->export->dix_protection_type;
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

static int fill_data4(data4 *d, off_t offset, size_t size, bool alloc_buffers)
{
	/*data4 *d = &rpc->read_plus_content4_u.rpc_data;*/
	void *data = NULL;

	if (size > 0 && alloc_buffers) {
		if (!(data = gsh_malloc_aligned(ALIGNMENT, size)))
			return NFS4ERR_SERVERFAULT;
	}


	d->d_offset = offset;
	d->d_allocated = true;
	d->d_data.d_data_len = size;
	d->d_data.d_data_val = data;

	return NFS4_OK;
}

static inline void clean_data4(data4 *d)
{
	gsh_free(d->d_data.d_data_val);
}

static int fill_data_protected(data_protected4 *pd, off_t offset, size_t size,
			       nfs_protection_info4 *pi, bool alloc_buffers)
{
	/*data_protected4 *pd = &rpc4->read_plus_content4_u.rpc_pdata;*/
	void *data = NULL;
	void *pi_data = NULL;
	size_t pi_size = 0;

	if (size > 0 && alloc_buffers) {
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
			      size_t size, nfs_protection_info4 *pi,
			      bool alloc_buffers)
{
	void *pi_data = NULL;
	size_t pi_size = 0;

	pi_size = get_pi_size(size);
	if (pi_size > 0 && alloc_buffers) {
		if (!(pi_data = gsh_malloc_aligned(ALIGNMENT, pi_size)))
			return NFS4ERR_SERVERFAULT;
	}

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

static int fill_data_plus(struct data_plus *dp, off_t offset, size_t size,
			  data_content4 content_type, nfs_protection_info4 *pi,
			  bool alloc_buffers)
{
	int ret = NFS4_OK;

	memset(dp, 0, sizeof(*dp));

	switch (content_type) {
	case NFS4_CONTENT_DATA:
		ret = fill_data4(&dp->u.data, offset, size, alloc_buffers);
		break;
	case NFS4_CONTENT_PROTECTED_DATA:
		ret = fill_data_protected(&dp->u.pdata, offset, size, pi,
					  alloc_buffers);
		break;
	case NFS4_CONTENT_PROTECT_INFO:
		ret = fill_protect_info4(&dp->u.pinfo, offset, size, pi,
					 alloc_buffers);
		break;
	case NFS4_CONTENT_APP_DATA_HOLE:
	case NFS4_CONTENT_HOLE:
	default:
		ret = NFS4ERR_NOTSUPP;
		LogMajor(COMPONENT_NFS_V4, "BUG: operations not supported "
			 "should not reach here.");
	}

	if (ret != NFS4_OK) {
		gsh_free(dp);
		return ret;
	}

	dp->content_type = content_type;

	return ret;
}

static void clean_data_plus(struct data_plus *dp)
{
	switch (dp->content_type) {
	case NFS4_CONTENT_DATA:
		clean_data4(&dp->u.data);
		break;
	case NFS4_CONTENT_PROTECTED_DATA:
		clean_data_protected4(&dp->u.pdata);
		break;
	case NFS4_CONTENT_PROTECT_INFO:
		clean_protect_info4(&dp->u.pinfo);
		break;
	case NFS4_CONTENT_APP_DATA_HOLE:
	case NFS4_CONTENT_HOLE:
	default:
		LogMajor(COMPONENT_NFS_V4, "BUG: operations not supported "
			 "should not reach here.");
	}
}

static int fill_read_plus_res(READ_PLUS4res *rp4res, size_t read_size,
			      struct data_plus *dp, bool eof)
{
	nfs_protection_info4 pi;
	read_plus_content4 *rpc4;
	read_plus_res4 *rpr4 = &rp4res->READ_PLUS4res_u.rp_resok4;
	int ret = 0;

	/*
	 * Right now, we support only one read_plus_content4.
	 * XXX: how to decide the number of read_plus_content4 if there are
	 * multiple?
	 */
	rpc4 = gsh_calloc(sizeof(*rpc4), 1);
	if (!rpc4) {
		rp4res->rp_status = NFS4ERR_SERVERFAULT;
		return rp4res->rp_status;
	}

	data_plus_to_read_plus_content(dp, rpc4);

	switch (dp->content_type) {
	case NFS4_CONTENT_DATA:
		rpc_data_data_len(rpc4) = read_size;
		break;
	case NFS4_CONTENT_PROTECTED_DATA:
		rpc_pdata_data_len(rpc4) = read_size;
		rpc_pdata_info_len(rpc4) = get_pi_size(read_size);
		break;
	case NFS4_CONTENT_PROTECT_INFO:
		rpc_pinfo_data_len(rpc4) = get_pi_size(read_size);
		break;
	case NFS4_CONTENT_APP_DATA_HOLE:
	case NFS4_CONTENT_HOLE:
	default:
		ret = NFS4ERR_NOTSUPP;
		LogMajor(COMPONENT_NFS_V4, "BUG: operations not supported "
			 "should not reach here.");
	}

	if (ret != NFS4_OK) {
		rp4res->rp_status = ret;
		gsh_free(rpc4);
		return ret;
	}

	rp4res->rp_status = NFS4_OK;

	rpc4->rpc_content = dp->content_type;

	rpr4->rpr_eof = eof;
	rpr4->rpr_contents.rpr_contents_len = 1;
	rpr4->rpr_contents.rpr_contents_val = rpc4;

	return NFS4_OK;
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
	struct data_plus data_plus;
	data_content4 content_type;
	nfs_protection_info4 pi;

	if (rp4args->rpa_content == NFS4_CONTENT_APP_DATA_HOLE ||
	    rp4args->rpa_content == NFS4_CONTENT_HOLE) {
		rp4res->rp_status = NFS4ERR_NOTSUPP;
		return rp4res->rp_status;
	}

	resp->resop = NFS4_OP_READ_PLUS;
	memset(rp4res, 0, sizeof(*rp4res));
	rp4res->rp_status = NFS4_OK;

	/* Do basic checks on a filehandle Only files can be read */
	rp4res->rp_status = nfs4_sanity_check_FH(compound, REGULAR_FILE, true);

	if (rp4res->rp_status != NFS4_OK)
		return rp4res->rp_status;

	if (nfs4_Is_Fh_DSHandle(&compound->currentFH)) {
		rp4res->rp_status = NFS4ERR_NOTSUPP;
		return rp4res->rp_status;
	}

	/* Manage access type MDONLY */
	if ((compound->export->access_type == ACCESSTYPE_MDONLY)
	    || (compound->export->access_type == ACCESSTYPE_MDONLY_RO)) {
		rp4res->rp_status = NFS4ERR_INVAL;
		return rp4res->rp_status;
	}

	entry = compound->current_entry;

	/* Check stateid correctness and get pointer to state (also
	 * checks for special stateids)
	 */
	rp4res->rp_status = nfs4_Check_Stateid(&rp4args->rpa_stateid,
					       entry,
					       &state_found,
					       compound,
					       STATEID_SPECIAL_ANY,
					       0,
					       false,
					       "READ_PLUS4");

	if (rp4res->rp_status != NFS4_OK)
		return rp4res->rp_status;

	/* NB: After this point, if state_found == NULL, then the
	 * stateid is all-0 or all-1
	 */
	if (state_found != NULL) {
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
			rp4res->rp_status = NFS4ERR_BAD_STATEID;
			LogDebug(COMPONENT_NFS_V4_LOCK,
				 "READ_PLUS with invalid statid of type %d",
				 state_found->state_type);
			return rp4res->rp_status;
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
				rp4res->rp_status = NFS4ERR_OPENMODE;
				LogDebug(COMPONENT_NFS_V4_LOCK,
					 "READ_PLUS state %p doesn't have "
					 "OPEN4_SHARE_ACCESS_READ",
					 state_found);
				return rp4res->rp_status;
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
				rp4res->rp_status = NFS4ERR_BAD_STATEID;
				return rp4res->rp_status;
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
			rp4res->rp_status = NFS4ERR_BAD_STATEID;
			return rp4res->rp_status;
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
		rp4res->rp_status = nfs4_check_special_stateid(
				entry, "READ_PLUS4", FATTR4_ATTR_READ);
		if (rp4res->rp_status != NFS4_OK) {
			PTHREAD_RWLOCK_unlock(&entry->state_lock);
			return rp4res->rp_status;
		}
	}

	if (state_open == NULL
	    && entry->obj_handle->attributes.owner !=
	    compound->req_ctx->creds->caller_uid) {
		/* Need to permission check the read. */
		cache_status = cache_inode_access(entry, FSAL_READ_ACCESS,
						  compound->req_ctx);

		if (cache_status == CACHE_INODE_FSAL_EACCESS) {
			/* Test for execute permission */
			cache_status = cache_inode_access(
				entry,
				FSAL_MODE_MASK_SET(FSAL_X_OK) |
				FSAL_ACE4_MASK_SET(FSAL_ACE_PERM_EXECUTE),
				compound->req_ctx);
		}

		if (cache_status != CACHE_INODE_SUCCESS) {
			rp4res->rp_status = nfs4_Errno(cache_status);
			goto done;
		}
	}

	offset = rp4args->rpa_offset;
	size = rp4args->rpa_count;
	content_type = rp4args->rpa_content;

	if (((compound->export->export_perms.options &
	      EXPORT_OPTION_MAXOFFSETREAD) == EXPORT_OPTION_MAXOFFSETREAD)
	    && ((offset + size) > compound->export->MaxOffsetRead)) {
		rp4res->rp_status = NFS4ERR_INVAL;
		goto done;
	}

	if (size > compound->export->MaxRead) {
		/* the client asked for too much data, this should normally
		   not happen because client will get FATTR4_MAXREAD value
		   at mount time */

		LogWarn(COMPONENT_NFS_V4,
			"NFS4_OP_READ_PLUS: read requested size = %"PRIu64
			" read allowed size = %" PRIu64,
			size, compound->export->MaxRead);
		size = compound->export->MaxRead;
	}

	get_protection_type4(compound, &pi);
	rp4res->rp_status = fill_data_plus(&data_plus, offset, size,
					   content_type, &pi, size > 0);
	if (rp4res->rp_status != NFS4_OK) {
		goto done;
	}

	/* If size == 0, no I/O is to be made and everything is
	 * alright
	 */
	if (size == 0) {
		/* A size = 0 can not lead to EOF */
		fill_read_plus_res(rp4res, 0, &data_plus, false);
		goto done;
	}

	if (!anonymous && compound->minorversion == 0) {
		compound->req_ctx->clientid =
		    &state_found->state_owner->so_owner.so_nfs4_owner.
		    so_clientid;
	}

	cache_status = cache_inode_rdwr_plus(entry, CACHE_INODE_READ_PLUS,
					     offset, size, &read_size,
					     bufferdata, &data_plus, &eof_met,
					     compound->req_ctx, &sync);

	if (cache_status != CACHE_INODE_SUCCESS) {
		rp4res->rp_status = nfs4_Errno(cache_status);
		clean_data_plus(&data_plus);
		goto done;
	}

	if (cache_inode_size(entry, compound->req_ctx, &file_size) !=
	    CACHE_INODE_SUCCESS) {
		rp4res->rp_status = nfs4_Errno(cache_status);
		clean_data_plus(&data_plus);
		goto done;
	}

	if (!anonymous && compound->minorversion == 0)
		compound->req_ctx->clientid = NULL;

	LogFullDebug(COMPONENT_NFS_V4,
		     "NFS4_OP_READ_PLUS: offset = %" PRIu64
		     " read length = %zu eof=%u",
		     offset, read_size, eof_met);

	eof_met = eof_met || ((offset + read_size) >= file_size);
	fill_read_plus_res(rp4res, read_size, &data_plus, eof_met);

done:
	if (anonymous)
		PTHREAD_RWLOCK_unlock(&entry->state_lock);

#ifdef USE_DBUS_STATS
	server_stats_io_done(compound->req_ctx, size, read_size,
			     rp4res->rp_status == NFS4_OK, false);
#endif

	return rp4res->rp_status;
}				/* nfs4_op_read */

/**
 * @brief Free data allocated for READ result.
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
	read_plus_res4 *rpr4 = &rp4res->READ_PLUS4res_u.rp_resok4;
	int rpc_len = rpr4->rpr_contents.rpr_contents_len;
	read_plus_content4 *rpc4s = rpr4->rpr_contents.rpr_contents_val;
	struct data_plus data_plus;
	int i;

	for (i = 0; i < rpc_len; ++i) {
		data_plus_from_read_plus_content(&data_plus, rpc4s + i);
		clean_data_plus(&data_plus);
	}

	gsh_free(rpc4s);
}				/* nfs4_op_read_Free */
