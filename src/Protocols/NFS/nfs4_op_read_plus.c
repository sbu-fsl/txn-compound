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

void fill_protection_info4(compound_data_t *compound, nfs_protection_info4 *pi)
{
	memset(pi, 0, sizeof(nfs_protection_info4));

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

	return pi;
}

static inline void fill_rpc4_data(read_plus_content4 *rpc4, off_t offset,
				  size_t dlen, char *data)
{
	data4 *d = &rpc->read_plus_content4_u.rpc_data;

	d->d_offset = offset;
	d->d_allocated = true;
	d->d_data.d_data_len = dlen;
	d->d_data.d_data_val = data;
}

static inline void free_rpc4_data(read_plus_content4 *rpc4)
{
	data4 *d = &rpc->read_plus_content4_u.rpc_data;

	gsh_free(d->d_data.d_data_val);
}

static inline void fill_rpc4_data_protected(read_plus_content4 *rpc4,
					    off_t offset,
					    size_t dlen, char *data,
					    nfs_protection_info4 *pi,
					    size_t pi_dlen, char *pi_data)
{
	data_protected4 *pd = &rpc4->read_plus_content4_u.rpc_pdata;

	pd->pd_type = *pi;
	pd->pd_offset = offset;
	pd->pd_allocated = true;
	pd->pd_data.pd_data_len = dlen;
	pd->pd_data.pd_data_val = data;
	pd->pd_info.pd_info_len = pi_dlen;
	pd->pd_info.pd_info_val = pi_data;
}

static inline void free_rpc4_data_protected(read_plus_content4 *rpc4)
{
	data_protected4 *pd = &rpc4->read_plus_content4_u.rpc_pdata;

	gsh_free(pd->pd_data.pd_data_val);
	gsh_free(pd->pd_info.pd_info_val);
}

static inline void fill_rpc4_protect_info4(read_plus_content4 *rpc4,
					   off_t offset,
					   nfs_protection_info4 *pi,
					   size_t pi_dlen, char *pi_data)
{
	data_protect_info4 *dpi = &rpc4->read_plus_content4_u.rpc_pinfo;

	dpi->pi_type = *pi;
	dpi->pi_offset = offset;
	dpi->pi_allocated = true;
	dpi->pi_data.pi_data_len = pi_dlen;
	dpi->pi_data.pi_data_val = pi_data;
}

static inline void free_rpc4_protect_info4(read_plus_content4 *rpc4)
{
	data_protect_info4 *dpi = &rpc4->read_plus_content4_u.rpc_pinfo;

	gsh_free(dpi->pi_data.pi_data_len);

}

static void build_read_plus_res(READ_PLUS4args *rp4args,
			        READ_PLUS4res *rp4res,
			        compound_data_t *compound,
			        size_t dlen, char *data,
			        size_t pi_dlen, char *pi_data,
			        bool eof)
{
	nfs_protection_info4 pi;
	read_plus_content4 *rpc4;
	read_plus_res4 *rpr4 = &rp4res->READ_PLUS4res_u.rp_resok4;
	off_t offset = rp4args->rpa_offset;

	*rpc4 = gsh_malloc(sizeof(read_plus_content4));
	if (!rpc4) {
		rp4res->rp_status = NFS4ERR_SERVERFAULT;
		return;
	}

	switch (rp4args->rpa_content) {
	case NFS4_CONTENT_DATA:
		fill_rpc4_data(rpc4, offset, dlen, data);
		break;
	case NFS4_CONTENT_PROTECTED_DATA:
		fill_protection_info4(compound, &pi);
		fill_rpc4_data_protected(rpc4, offset, dlen, data,
					 pi, pi_dlen, pi_data);
		break;
	case NFS4_CONTENT_PROTECT_INFO:
		fill_protection_info4(compound, &pi);
		fill_rpc4_protect_info4(rpc4, offset, pi, pi_dlen, pi_data);
		break;
	case NFS4_CONTENT_APP_DATA_HOLE:
	case NFS4_CONTENT_HOLE:
	default:
		rp4res->rp_status = NFS4ERR_NOTSUPP;
		gsh_free(rpc4);
		LogMajor(COMPONENT_NFS_V4, "BUG: operations not supported "
			 "should not reach here.");
		return;
	}

	rpc4->rpc_content = rp4args->rpa_content;

	rp4res->rp_status = NFS4_OK;

	rpr4->rpr_eof = eof;
	rpr4->rpr_contents_len = 1;
	rpr4->rpr_contents_val = rpc4;
}

/*
 * REQUIRES: the result status is NFS4_OK.
 */
static void free_read_plus_res(READ_PLUSres *rp4res)
{
	read_plus_res4 *rpr4 = &rp4res->READ_PLUS4res_u.rp_resok4;
	int rpc_len = rpr4->rpr_contents.rpr_contents_len;
	read_plus_content4 *rpc4s = rpr4->rpr_contents_val;

	for (int i = 0; i < rpc_len; ++i) {
		switch (rpc4s[i].rpc_content) {
		case NFS4_CONTENT_DATA:
			free_rpc4_data(rpc4s + i);
			break;
		case NFS4_CONTENT_PROTECTED_DATA:
			free_rpc4_data_protected(rpc4s + i);
			break;
		case NFS4_CONTENT_PROTECT_INFO:
			free_rpc4_protect_info4(rpc4s + i);
			break;
		case NFS4_CONTENT_APP_DATA_HOLE:
		case NFS4_CONTENT_HOLE:
		default:
			LogMajor(COMPONENT_NFS_V4, "BUG: operations not supported "
				 "should not reach here.");
			continue;
		}
	}

	gsh_free(rpc4s);
}

int nfs4_op_read_plus(struct nfs_argop4 *op, compound_data_t *compound,
		      struct nfs_resop4 *resp)
{
	READ_PLUS4args * const rp4args = &op->nfs_argop4_u.opreadplus;
	READ_PLUS4res * const rp4res = &resp->nfs_resop4_u.opreadplus;
	uint64_t size = 0;
	size_t read_size = 0;
	uint64_t offset = 0;
	bool eof_met = false;
	void *bufferdata = NULL;
	size_t pi_dlen = 0;
	void *pi_data = NULL;
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

	if (rp4args->data_content4 == NFS4_CONTENT_APP_DATA_HOLE ||
	    rp4args->data_content4 == NFS4_CONTENT_HOLE) {
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
		rp4res->rp_status = NFS4ERR_DQUOT;
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
				 "READ with invalid statid of type %d",
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
					 "READ state %p doesn't have "
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

	/* Get the size and offset of the read operation */
	offset = rp4args->rpa_offset;
	size = rp4args->rpa_count;

	if (((compound->export->export_perms.options &
	      EXPORT_OPTION_MAXOFFSETREAD) == EXPORT_OPTION_MAXOFFSETREAD)
	    && ((offset + size) > compound->export->MaxOffsetRead)) {
		rp4res->rp_status = NFS4ERR_DQUOT;
		goto done;
	}

	if (size > compound->export->MaxRead) {
		/* the client asked for too much data, this should normally
		   not happen because client will get FATTR4_MAXREAD value
		   at mount time */

		LogFullDebug(COMPONENT_NFS_V4,
			     "NFS4_OP_READ_PLUS: read requested size = %"PRIu64
			     " read allowed size = %" PRIu64,
			     size, compound->export->MaxRead);
		size = compound->export->MaxRead;
	}

	/* If size == 0, no I/O is to be made and everything is
	 * alright
	 */
	if (size == 0) {
		/* A size = 0 can not lead to EOF */
		build_read_plus_res(rp4args, rp4res, compound,
				    0, NULL, 0, NULL, false);
		goto done;
	}

	/* Some work is to be done */
	bufferdata = gsh_malloc_aligned(4096, size);

	if (bufferdata == NULL) {
		LogEvent(COMPONENT_NFS_V4, "FAILED to allocate bufferdata");
		rp4res->rp_status = NFS4ERR_SERVERFAULT;
		goto done;
	}

	pi_dlen = get_pi_size(size);
	pi_data = gsh_malloc_aligned(4096, pi_dlen);
	if (pi_data == NULL) {
		LogEvent(COMPONENT_NFS_V4, "FAILED to allocate pi_data");
		gsh_free(bufferdata);
		rp4res->rp_status = NFS4ERR_SERVERFAULT;
		goto done;
	}

	if (!anonymous && compound->minorversion == 0) {
		compound->req_ctx->clientid =
		    &state_found->state_owner->so_owner.so_nfs4_owner.
		    so_clientid;
	}

	cache_status = cache_inode_rdwr_plus(entry, CACHE_INODE_READ_PLUS,
					     offset, size, &read_size,
					     bufferdata, data_plus, &eof_met,
					     compound->req_ctx, &sync);

	if (cache_status != CACHE_INODE_SUCCESS) {
		rp4res->rp_status = nfs4_Errno(cache_status);
		gsh_free(bufferdata);
		gsh_free(pi_data);
		goto done;
	}

	if (cache_inode_size(entry, compound->req_ctx, &file_size) !=
	    CACHE_INODE_SUCCESS) {
		rp4res->rp_status = nfs4_Errno(cache_status);
		gsh_free(bufferdata);
		gsh_free(pi_data);
		goto done;
	}

	if (!anonymous && compound->minorversion == 0)
		compound->req_ctx->clientid = NULL;

	LogFullDebug(COMPONENT_NFS_V4,
		     "NFS4_OP_READ_PLUS: offset = %" PRIu64
		     " read length = %zu eof=%u",
		     offset, read_size, eof_met);

	eof_met = eof_met || ((offset + read_size) >= file_size);
	build_read_plus_res(rp4args, rp4res, compound, read_size, bufferdata,
			    pi_dlen, pi_data, eof_met);

	/* Say it is ok */
	rp4res->rp_status = NFS4_OK;

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
	READ_PLUS4res * const rp4res = &res->nfs_resop4_u.opreadplus;

	if (rp4res->status == NFS4_OK) {
		free_read_plus_res(rp4res);
	}

	return;
}				/* nfs4_op_read_Free */
