/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright CEA/DAM/DIF  (2008)
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *
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
 * @file nfs4_op_write.c
 * @brief Routines used for managing the NFS4 COMPOUND functions.
 *
 * Routines used for managing the NFS4 COMPOUND functions.
 */

#include "config.h"
#include "log.h"
#include "ganesha_rpc.h"
#include "nfs4.h"
#include "nfs_core.h"
#include "sal_functions.h"
#include "nfs_proto_functions.h"
#include "nfs_proto_tools.h"
#include "fsal_pnfs.h"
#include "server_stats.h"
#include "nfs_integrity.h"


static void fill_write_plus_res(WRITE_PLUS4res *wp4res,
				size_t count, int stable,
				void (*get_verifier) (struct gsh_buffdesc
						      *verf_desc))
{
	struct gsh_buffdesc verf_desc;
	write_response4 *wr4 = &wp4res->WRITE_PLUS4res_u.wp_resok4;

	memset(&wr4->wr_callback_id, 0, sizeof(wr4->wr_callback_id));
	wr4->wr_count = count;
	wr4->wr_committed = stable;

	verf_desc.addr = &wr4->wr_writeverf;
	verf_desc.len = sizeof(verifier4);
	get_verifier(&verf_desc);

	wp4res->wp_status = NFS4_OK;
}

int nfs4_op_write_plus(struct nfs_argop4 *op, compound_data_t *compound,
		       struct nfs_resop4 *resp)
{
	WRITE_PLUS4args * const wp4args = &op->nfs_argop4_u.opwrite_plus;
	WRITE_PLUS4res * const wp4res = &resp->nfs_resop4_u.opwrite_plus;
	uint64_t size;
	size_t written_size;
	uint64_t offset;
	bool eof_met;
	bool sync = wp4args->wp_stable != UNSTABLE4;
	void *bufferdata;
	stable_how4 stable_how;
	state_t *state_found = NULL;
	state_t *state_open = NULL;
	cache_inode_status_t cache_status = CACHE_INODE_SUCCESS;
	cache_entry_t *entry = NULL;
	fsal_status_t fsal_status;
	/* This flag is set to true in the case of an anonymous read so that
	   we know to release the state lock afterward.  The state lock does
	   not need to be held during a non-anonymous read, since the open
	   state itself prevents a conflict. */
	bool anonymous = false;
	struct data_plus data_plus;
	struct export_ops *fsal_ops = compound->export->export_hdl->ops;


	/* Lock are not supported */
	resp->resop = NFS4_OP_WRITE_PLUS;
	wp4res->wp_status = NFS4_OK;

	/*
	 * Do basic checks on a filehandle
	 * Only files can be written
	 */
	wp4res->wp_status = nfs4_sanity_check_FH(compound, REGULAR_FILE, true);
	if (wp4res->wp_status != NFS4_OK)
		return wp4res->wp_status;

	/* if quota support is active, then we should check is the FSAL
	   allows inode creation or not */
	fsal_status = fsal_ops->check_quota(compound->export->export_hdl,
					    compound->export->fullpath,
					    FSAL_QUOTA_INODES,
					    compound->req_ctx);

	if (FSAL_IS_ERROR(fsal_status)) {
		wp4res->wp_status = NFS4ERR_DQUOT;
		return wp4res->wp_status;
	}

	if ((compound->minorversion == 1)
	    && (nfs4_Is_Fh_DSHandle(&compound->currentFH))) {
		wp4res->wp_status = NFS4ERR_NOTSUPP;
		return wp4res->wp_status;
	}


	/* Manage access type */
	switch (compound->export->access_type) {
	case ACCESSTYPE_MDONLY:
	case ACCESSTYPE_MDONLY_RO:
		wp4res->wp_status = NFS4ERR_DQUOT;
		return wp4res->wp_status;
		break;

	case ACCESSTYPE_RO:
		wp4res->wp_status = NFS4ERR_ROFS;
		return wp4res->wp_status;
		break;

	default:
		break;
	}			/* switch( compound->export->access_type ) */

	/* vnode to manage is the current one */
	entry = compound->current_entry;

	/* Check stateid correctness and get pointer to state
	 * (also checks for special stateids)
	 */
	wp4res->wp_status = nfs4_Check_Stateid(&wp4args->wp_stateid, entry,
					       &state_found, compound,
					       STATEID_SPECIAL_ANY, 0, false,
					       "WRITE_PLUS");

	if (wp4res->wp_status != NFS4_OK)
		return wp4res->wp_status;

	/* NB: After this points, if state_found == NULL, then
	 * the stateid is all-0 or all-1
	 */
	if (state_found != NULL) {
		switch (state_found->state_type) {
		case STATE_TYPE_SHARE:
			state_open = state_found;
			/** @todo FSF: need to check against existing locks */
			break;

		case STATE_TYPE_LOCK:
			state_open = state_found->state_data.lock.openstate;
			/**
			 * @todo FSF: should check that write is in range of an
			 * exclusive lock...
			 */
			break;

		case STATE_TYPE_DELEG:
			/**
			 * @todo FSF: should check that this is a write
			 * delegation?
			 */
		case STATE_TYPE_LAYOUT:
			state_open = NULL;
			break;

		default:
			wp4res->wp_status = NFS4ERR_BAD_STATEID;
			LogDebug(COMPONENT_NFS_V4_LOCK,
				 "WRITE with invalid stateid of type %d",
				 (int)state_found->state_type);
			return wp4res->wp_status;
		}

		/* This is a write operation, this means that the file
		 * MUST have been opened for writing
		 */
		if (state_open != NULL &&
		    (state_open->state_data.share.share_access &
		     OPEN4_SHARE_ACCESS_WRITE) == 0) {
			/* Bad open mode, return NFS4ERR_OPENMODE */
			wp4res->wp_status = NFS4ERR_OPENMODE;
			LogDebug(COMPONENT_NFS_V4_LOCK,
				 "WRITE state %p doesn't have OPEN4_SHARE_ACCESS_WRITE",
				 state_found);
			return wp4res->wp_status;
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
		wp4res->wp_status =
		    nfs4_check_special_stateid(entry,
					       "WRITE",
					       FATTR4_ATTR_WRITE);

		if (wp4res->wp_status != NFS4_OK) {
			PTHREAD_RWLOCK_unlock(&entry->state_lock);
			return wp4res->wp_status;
		}
	}

	if (state_open == NULL
	    && entry->obj_handle->attributes.owner !=
	    compound->req_ctx->creds->caller_uid) {
		cache_status = cache_inode_access(entry,
						  FSAL_WRITE_ACCESS,
						  compound->req_ctx);

		if (cache_status != CACHE_INODE_SUCCESS) {
			wp4res->wp_status = nfs4_Errno(cache_status);
			goto out;
		}
	}

	/* Get the characteristics of the I/O to be made */
	if (wp4args->wp_data.wp_data_len != 1) {
		wp4res->wp_status = NFS4ERR_INVAL;
		LogWarn(COMPONENT_NFS_V4,
			"NFS4_OP_WRITE_PLUS has %d (not 1) arguments.",
			wp4args->wp_data.wp_data_len);
		return wp4res->wp_status;
	}

	data_plus_from_write_plus_args(&data_plus,
				       wp4args->wp_data.wp_data_val);

	offset = data_plus_to_offset(&data_plus);
	size = data_plus_to_file_dlen(&data_plus);
	stable_how = wp4args->wp_stable;
	LogFullDebug(COMPONENT_NFS_V4,
		     "NFS4_OP_WRITE_PLUS: offset = %" PRIu64 "  length = %"
		     PRIu64 "  stable = %d",
		     offset, size, stable_how);

	if ((compound->export->export_perms.options &
	     EXPORT_OPTION_MAXOFFSETWRITE) == EXPORT_OPTION_MAXOFFSETWRITE)
		if ((offset + size) > compound->export->MaxOffsetWrite) {
			wp4res->wp_status = NFS4ERR_DQUOT;
			goto out;
		}

	if (size > compound->export->MaxWrite) {
		/*
		 * The client asked for too much data, we
		 * must restrict him
		 */

		LogFullDebug(COMPONENT_NFS_V4,
			     "NFS4_OP_WRITE_PLUS: write requested size = %"
			     PRIu64 " write allowed size = %" PRIu64,
			     size, compound->export->MaxWrite);

		size = compound->export->MaxWrite;
	}

	/* Where are the data ? */
	bufferdata = data_plus_to_file_data(&data_plus);

	LogFullDebug(COMPONENT_NFS_V4,
		     "NFS4_OP_WRITE_PLUS: offset = %" PRIu64 " length = %"
		     PRIu64, offset, size);

	/* if size == 0 , no I/O) are actually made and everything is alright */
	if (size == 0) {
		fill_write_plus_res(wp4res, 0, FILE_SYNC4,
				    fsal_ops->get_write_verifier);
		goto out;
	}

	if (!anonymous && compound->minorversion == 0) {
		compound->req_ctx->clientid =
		    &state_found->state_owner->so_owner.so_nfs4_owner.
		    so_clientid;
	}

	cache_status = cache_inode_rdwr_plus(entry, CACHE_INODE_WRITE_PLUS,
					     offset, size, &written_size,
					     bufferdata, &data_plus, &eof_met,
					     compound->req_ctx, &sync);

	if (cache_status != CACHE_INODE_SUCCESS) {
		LogDebug(COMPONENT_NFS_V4,
			 "cache_inode_rdwr returned %s",
			 cache_inode_err_str(cache_status));
		wp4res->wp_status = nfs4_Errno(cache_status);
		goto out;
	}

	if (!anonymous && compound->minorversion == 0)
		compound->req_ctx->clientid = NULL;

	fill_write_plus_res(wp4res, written_size,
			    sync ? FILE_SYNC4 : UNSTABLE4,
			    fsal_ops->get_write_verifier);

out:
	if (anonymous)
		PTHREAD_RWLOCK_unlock(&entry->state_lock);

#ifdef USE_DBUS_STATS
	server_stats_io_done(compound->req_ctx, size, written_size,
			     (wp4res->wp_status == NFS4_OK), true);
#endif

	return wp4res->wp_status;
}				/* nfs4_op_write */

/**
 * @brief Free memory allocated for WRITE result
 *
 * This function frees any memory allocated for the result of the
 * NFS4_OP_WRITE_PLUS operation.
 *
 * @param[in,out] resp nfs4_op results
*
 */
void nfs4_op_write_plus_Free(nfs_resop4 *resp)
{
	/* Nothing to be done */
	return;
}				/* nfs4_op_write_Free */
