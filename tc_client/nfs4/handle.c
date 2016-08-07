/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) Stony Brook University 2014
 * by Ming Chen <v.mingchen@gmail.com>
 *
 * Copyright (C) Max Matveev, 2012
 * Copyright CEA/DAM/DIF  (2008)
 *
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

/* Proxy handle methods */

#include "config.h"

#include "fsal.h"
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/types.h>
#include "ganesha_list.h"
#include "abstract_atomic.h"
#include "fsal_types.h"
#include "FSAL/fsal_commonlib.h"
#include "fs_fsal_methods.h"
#include "fsal_nfsv4_macros.h"
#include "fsal_convert.h"
#include "nfs_proto_functions.h"
#include "nfs_proto_tools.h"
#include "export_mgr.h"
#include "nfs4_util.h"
#include "tc_helper.h"
#include "session_slots.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "path_utils.h"

#include <stdlib.h>
/*#include <sys/param.h>*/

#define FSAL_PROXY_NFS_V4 4

#define TC_FILE_START 0

static clientid4 fs_clientid;
static clientid4 tc_clientid;
static sessionid4 fs_sessionid;
static sequenceid4 fs_sequenceid;  /* per-ClientID sequence for creating sessions */
static pthread_mutex_t fs_clientid_mutex = PTHREAD_MUTEX_INITIALIZER;
static char fs_hostname[MAXNAMLEN + 1];
static pthread_t fs_recv_thread;
static pthread_t fs_renewer_thread;
static struct glist_head rpc_calls;
static struct glist_head free_contexts;
static int rpc_sock = -1;
static uint32_t rpc_xid;
static pthread_mutex_t listlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sockless = PTHREAD_COND_INITIALIZER;
static pthread_cond_t need_context = PTHREAD_COND_INITIALIZER;

static struct session_slot_table *sess_slot_tbl;

static pthread_once_t tc_once;
static pthread_key_t tc_compound_resources;

#define MAX_NUM_OPS_PER_COMPOUND 256
static __thread nfs_argop4 argoparray[MAX_NUM_OPS_PER_COMPOUND];
static __thread nfs_resop4 resoparray[MAX_NUM_OPS_PER_COMPOUND];
static __thread int opcnt = 0;
static __thread bool slot_allocated = false;

static __thread char tc_saved_path[PATH_MAX + 1];

#define MAX_BUFS_PER_COMPOUND (MAX_NUM_OPS_PER_COMPOUND * 4)
static __thread int tc_bufcnt;
static __thread char* tc_bufs[MAX_BUFS_PER_COMPOUND];

/*
 * Protects the "free_contexts" list and the "need_context" condition.
 */
static pthread_mutex_t context_lock = PTHREAD_MUTEX_INITIALIZER;

/* NB! nfs_prog is just an easy way to get this info into the call
 *     It should really be fetched via export pointer */
struct fs_rpc_io_context {
	pthread_mutex_t iolock;
	pthread_cond_t iowait;
	struct glist_head calls;
	uint32_t rpc_xid;
	int iodone;
	int ioresult;
	unsigned int nfs_prog;
	unsigned int sendbuf_sz;
	unsigned int recvbuf_sz;
	char *sendbuf;
	char *recvbuf;
};

/* Use this to estimate storage requirements for fattr4 blob */
struct fs_fattr_storage {
	fattr4_type type;
	fattr4_change change_time;
	fattr4_size size;
	fattr4_fsid fsid;
	fattr4_filehandle filehandle;
	fattr4_fileid fileid;
	fattr4_mode mode;
	fattr4_numlinks numlinks;
	fattr4_owner owner;
	fattr4_owner_group owner_group;
	fattr4_space_used space_used;
	fattr4_time_access time_access;
	fattr4_time_metadata time_metadata;
	fattr4_time_modify time_modify;
	fattr4_rawdev rawdev;
	char padowner[MAXNAMLEN + 1];
	char padgroup[MAXNAMLEN + 1];
	char padfh[NFS4_FHSIZE];
};

#define FATTR_BLOB_SZ sizeof(struct fs_fattr_storage)

/*
 * This is what becomes an opaque FSAL handle for the upper layers.
 *
 * The type is a placeholder for future expansion.
 */
struct fs_handle_blob {
	uint8_t len;
	uint8_t type;
	uint8_t bytes[0];
};

struct fs_obj_handle {
	struct fsal_obj_handle obj;
	nfs_fh4 fh4;
#ifdef PROXY_HANDLE_MAPPING
	nfs23_map_handle_t h23;
#endif
	fsal_openflags_t openflags;
	struct fs_handle_blob blob;
};

struct tc_cwd_data {
        char path[PATH_MAX];
        char fhbuf[NFS4_FHSIZE];
        nfs_fh4 fh;
        int32_t refcount;
};

static struct tc_cwd_data *tc_cwd = NULL;
static pthread_mutex_t tc_cwd_lock = PTHREAD_MUTEX_INITIALIZER;

static struct tc_cwd_data *tc_get_cwd()
{
        struct tc_cwd_data *cwd;
        pthread_mutex_lock(&tc_cwd_lock);
        assert(tc_cwd);
        cwd = tc_cwd;
        pthread_mutex_unlock(&tc_cwd_lock);
        atomic_inc_int32_t(&cwd->refcount);
        return cwd;
}

/* A special stateid to use the current stateid on the server side. */
static const stateid4 CURSID = {
        .seqid = 1U,
};

static void tc_put_cwd(struct tc_cwd_data *cwd)
{
        if (atomic_dec_int32_t(&cwd->refcount) == 0) {
                free(cwd);
        }
}

static struct fs_obj_handle *fs_alloc_handle(struct fsal_export *exp,
					       const nfs_fh4 *fh,
					       const struct attrlist *attr);

static int nfsstat4_to_errno(nfsstat4 nfsstat)
{
	if (nfsstat <= NFS4ERR_MLINK) { /* 31 */
		return nfsstat;
	} else if (nfsstat == NFS4ERR_NAMETOOLONG) { /* 63 */
		return ENAMETOOLONG;
	} else if (nfsstat == NFS4ERR_NOTEMPTY) { /* 66 */
		return ENOTEMPTY;
	} else if (nfsstat == NFS4ERR_DQUOT) { /* 69 */
		return EDQUOT;
	} else if (nfsstat == NFS4ERR_STALE) { /* 70 */
		return ESTALE;
        } else {
		assert(nfsstat >= NFS4ERR_BADHANDLE); /* 10001 */
		return EREMOTEIO;
        }
}

static fsal_status_t nfsstat4_to_fsal(nfsstat4 nfsstatus)
{
	switch (nfsstatus) {
	case NFS4ERR_SAME:
	case NFS4ERR_NOT_SAME:
	case NFS4_OK:
		return fsalstat(ERR_FSAL_NO_ERROR, (int)nfsstatus);
	case NFS4ERR_PERM:
		return fsalstat(ERR_FSAL_PERM, (int)nfsstatus);
	case NFS4ERR_NOENT:
		return fsalstat(ERR_FSAL_NOENT, (int)nfsstatus);
	case NFS4ERR_IO:
		return fsalstat(ERR_FSAL_IO, (int)nfsstatus);
	case NFS4ERR_NXIO:
		return fsalstat(ERR_FSAL_NXIO, (int)nfsstatus);
	case NFS4ERR_EXPIRED:
	case NFS4ERR_LOCKED:
	case NFS4ERR_SHARE_DENIED:
	case NFS4ERR_LOCK_RANGE:
	case NFS4ERR_OPENMODE:
	case NFS4ERR_FILE_OPEN:
	case NFS4ERR_ACCESS:
	case NFS4ERR_DENIED:
		return fsalstat(ERR_FSAL_ACCESS, (int)nfsstatus);
	case NFS4ERR_EXIST:
		return fsalstat(ERR_FSAL_EXIST, (int)nfsstatus);
	case NFS4ERR_XDEV:
		return fsalstat(ERR_FSAL_XDEV, (int)nfsstatus);
	case NFS4ERR_NOTDIR:
		return fsalstat(ERR_FSAL_NOTDIR, (int)nfsstatus);
	case NFS4ERR_ISDIR:
		return fsalstat(ERR_FSAL_ISDIR, (int)nfsstatus);
	case NFS4ERR_FBIG:
		return fsalstat(ERR_FSAL_FBIG, 0);
	case NFS4ERR_NOSPC:
		return fsalstat(ERR_FSAL_NOSPC, (int)nfsstatus);
	case NFS4ERR_ROFS:
		return fsalstat(ERR_FSAL_ROFS, (int)nfsstatus);
	case NFS4ERR_MLINK:
		return fsalstat(ERR_FSAL_MLINK, (int)nfsstatus);
	case NFS4ERR_NAMETOOLONG:
		return fsalstat(ERR_FSAL_NAMETOOLONG, (int)nfsstatus);
	case NFS4ERR_NOTEMPTY:
		return fsalstat(ERR_FSAL_NOTEMPTY, (int)nfsstatus);
	case NFS4ERR_DQUOT:
		return fsalstat(ERR_FSAL_DQUOT, (int)nfsstatus);
	case NFS4ERR_STALE:
		return fsalstat(ERR_FSAL_STALE, (int)nfsstatus);
	case NFS4ERR_NOFILEHANDLE:
	case NFS4ERR_BADHANDLE:
		return fsalstat(ERR_FSAL_BADHANDLE, (int)nfsstatus);
	case NFS4ERR_BAD_COOKIE:
		return fsalstat(ERR_FSAL_BADCOOKIE, (int)nfsstatus);
	case NFS4ERR_NOTSUPP:
		return fsalstat(ERR_FSAL_NOTSUPP, (int)nfsstatus);
	case NFS4ERR_TOOSMALL:
		return fsalstat(ERR_FSAL_TOOSMALL, (int)nfsstatus);
	case NFS4ERR_SERVERFAULT:
		return fsalstat(ERR_FSAL_SERVERFAULT, (int)nfsstatus);
	case NFS4ERR_BADTYPE:
		return fsalstat(ERR_FSAL_BADTYPE, (int)nfsstatus);
	case NFS4ERR_GRACE:
	case NFS4ERR_DELAY:
		return fsalstat(ERR_FSAL_DELAY, (int)nfsstatus);
	case NFS4ERR_FHEXPIRED:
		return fsalstat(ERR_FSAL_FHEXPIRED, (int)nfsstatus);
	case NFS4ERR_WRONGSEC:
		return fsalstat(ERR_FSAL_SEC, (int)nfsstatus);
	case NFS4ERR_SYMLINK:
		return fsalstat(ERR_FSAL_SYMLINK, (int)nfsstatus);
	case NFS4ERR_ATTRNOTSUPP:
		return fsalstat(ERR_FSAL_ATTRNOTSUPP, (int)nfsstatus);
	case NFS4ERR_INVAL:
	case NFS4ERR_CLID_INUSE:
	case NFS4ERR_MOVED:
	case NFS4ERR_RESOURCE:
	case NFS4ERR_MINOR_VERS_MISMATCH:
	case NFS4ERR_STALE_CLIENTID:
	case NFS4ERR_STALE_STATEID:
	case NFS4ERR_OLD_STATEID:
	case NFS4ERR_BAD_STATEID:
	case NFS4ERR_BAD_SEQID:
	case NFS4ERR_RESTOREFH:
	case NFS4ERR_LEASE_MOVED:
	case NFS4ERR_NO_GRACE:
	case NFS4ERR_RECLAIM_BAD:
	case NFS4ERR_RECLAIM_CONFLICT:
	case NFS4ERR_BADXDR:
	case NFS4ERR_BADCHAR:
	case NFS4ERR_BADNAME:
	case NFS4ERR_BAD_RANGE:
	case NFS4ERR_BADOWNER:
	case NFS4ERR_OP_ILLEGAL:
	case NFS4ERR_LOCKS_HELD:
	case NFS4ERR_LOCK_NOTSUPP:
	case NFS4ERR_DEADLOCK:
	case NFS4ERR_ADMIN_REVOKED:
	case NFS4ERR_CB_PATH_DOWN:
	default:
		return fsalstat(ERR_FSAL_INVAL, (int)nfsstatus);
	}
}

#define PXY_ATTR_BIT(b) (1U << b)
#define PXY_ATTR_BIT2(b) (1U << (b - 32))

static struct bitmap4 fs_bitmap_getattr = {
	.map[0] =
	    (PXY_ATTR_BIT(FATTR4_TYPE) | PXY_ATTR_BIT(FATTR4_CHANGE) |
	     PXY_ATTR_BIT(FATTR4_SIZE) | PXY_ATTR_BIT(FATTR4_FSID) |
	     PXY_ATTR_BIT(FATTR4_FILEID)),
	.map[1] =
	    (PXY_ATTR_BIT2(FATTR4_MODE) | PXY_ATTR_BIT2(FATTR4_NUMLINKS) |
	     PXY_ATTR_BIT2(FATTR4_OWNER) | PXY_ATTR_BIT2(FATTR4_OWNER_GROUP) |
	     PXY_ATTR_BIT2(FATTR4_SPACE_USED) |
	     PXY_ATTR_BIT2(FATTR4_TIME_ACCESS) |
	     PXY_ATTR_BIT2(FATTR4_TIME_METADATA) |
	     PXY_ATTR_BIT2(FATTR4_TIME_MODIFY) | PXY_ATTR_BIT2(FATTR4_RAWDEV)),
	.bitmap4_len = 2
};

/* Until readdir callback can take more information do not ask for more then
 * just type */
static struct bitmap4 fs_bitmap_readdir = {
	.map[0] = PXY_ATTR_BIT(FATTR4_TYPE),
	.bitmap4_len = 1
};

/**
 * XXX: FATTR4_FILEHANDLE?
 */
static struct bitmap4 tc_bitmap_readdir = {
	.map[0] = PXY_ATTR_BIT(FATTR4_TYPE) |
		  PXY_ATTR_BIT(FATTR4_RDATTR_ERROR),
	.bitmap4_len = 1
};

static struct bitmap4 fs_bitmap_fsinfo = {
	.map[0] =
	    (PXY_ATTR_BIT(FATTR4_FILES_AVAIL) | PXY_ATTR_BIT(FATTR4_FILES_FREE)
	     | PXY_ATTR_BIT(FATTR4_FILES_TOTAL)),
	.map[1] =
	    (PXY_ATTR_BIT2(FATTR4_SPACE_AVAIL) |
	     PXY_ATTR_BIT2(FATTR4_SPACE_FREE) |
	     PXY_ATTR_BIT2(FATTR4_SPACE_TOTAL)),
	.bitmap4_len = 2
};

static struct bitmap4 lease_bits = {
	.map[0] = PXY_ATTR_BIT(FATTR4_LEASE_TIME),
	.bitmap4_len = 1
};

static void tc_attr_masks_to_bitmap(const struct tc_attrs_masks *masks,
                                    bitmap4 *bm)
{
        memset(bm, 0, sizeof(*bm));
        if (masks->has_mode) {
                bm->map[0] |= PXY_ATTR_BIT(FATTR4_TYPE);
                bm->map[1] |= PXY_ATTR_BIT2(FATTR4_MODE);
                bm->bitmap4_len = MAX(bm->bitmap4_len, 2);
        }
        if (masks->has_size) {
                bm->map[0] |= PXY_ATTR_BIT(FATTR4_SIZE);
                bm->bitmap4_len = MAX(bm->bitmap4_len, 1);
        }
        if (masks->has_nlink) {
                bm->map[1] |= PXY_ATTR_BIT2(FATTR4_NUMLINKS);
                bm->bitmap4_len = MAX(bm->bitmap4_len, 2);
        }
        if (masks->has_fileid) {
                bm->map[0] |= PXY_ATTR_BIT(FATTR4_FILEID);
                bm->bitmap4_len = MAX(bm->bitmap4_len, 1);
        }
        if (masks->has_blocks) {
                bm->map[1] |= PXY_ATTR_BIT2(FATTR4_SPACE_USED);
                bm->bitmap4_len = MAX(bm->bitmap4_len, 2);
        }
        if (masks->has_uid) {
                bm->map[1] |= PXY_ATTR_BIT2(FATTR4_OWNER);
                bm->bitmap4_len = MAX(bm->bitmap4_len, 2);
        }
        if (masks->has_gid) {
                bm->map[1] |= PXY_ATTR_BIT2(FATTR4_OWNER_GROUP);
                bm->bitmap4_len = MAX(bm->bitmap4_len, 2);
        }
        if (masks->has_rdev) {
                bm->map[1] |= PXY_ATTR_BIT2(FATTR4_RAWDEV);
                bm->bitmap4_len = MAX(bm->bitmap4_len, 2);
        }
        if (masks->has_atime) {
                bm->map[1] |= PXY_ATTR_BIT2(FATTR4_TIME_ACCESS);
                bm->bitmap4_len = MAX(bm->bitmap4_len, 2);
        }
        if (masks->has_mtime) {
                bm->map[1] |= PXY_ATTR_BIT2(FATTR4_TIME_MODIFY);
                bm->bitmap4_len = MAX(bm->bitmap4_len, 2);
        }
        if (masks->has_ctime) {
                bm->map[1] |= PXY_ATTR_BIT2(FATTR4_TIME_METADATA);
                bm->bitmap4_len = MAX(bm->bitmap4_len, 2);
        }
}

#undef PXY_ATTR_BIT
#undef PXY_ATTR_BIT2

static struct {
	attrmask_t mask;
	int fattr_bit;
} fsal_mask2bit[] = {
	{
	ATTR_SIZE, FATTR4_SIZE}, {
	ATTR_MODE, FATTR4_MODE}, {
	ATTR_OWNER, FATTR4_OWNER}, {
	ATTR_GROUP, FATTR4_OWNER_GROUP}, {
	ATTR_ATIME, FATTR4_TIME_ACCESS_SET}, {
	ATTR_ATIME_SERVER, FATTR4_TIME_ACCESS_SET}, {
	ATTR_MTIME, FATTR4_TIME_MODIFY_SET}, {
	ATTR_MTIME_SERVER, FATTR4_TIME_MODIFY_SET}, {
	ATTR_CTIME, FATTR4_TIME_METADATA}
};

static struct bitmap4 empty_bitmap = {
	.map[0] = 0,
	.map[1] = 0,
	.map[2] = 0,
	.bitmap4_len = 2
};

static bool is_special_stateid(const stateid4 *sid)
{
	static const char All_Zero[] =
	    "\0\0\0\0\0\0\0\0\0\0\0\0"; /* 12 times \0 */
        return memcmp(sid->other, All_Zero, 12) == 0;
}

static int fs_fsalattr_to_fattr4(const struct attrlist *attrs, fattr4 *data)
{
	int i;
	struct bitmap4 bmap = empty_bitmap;
	struct xdr_attrs_args args;

	for (i = 0; i < ARRAY_SIZE(fsal_mask2bit); i++) {
		if (FSAL_TEST_MASK(attrs->mask, fsal_mask2bit[i].mask)) {
			if (fsal_mask2bit[i].fattr_bit > 31) {
				bmap.map[1] |=
				    1U << (fsal_mask2bit[i].fattr_bit - 32);
				bmap.bitmap4_len = 2;
			} else {
				bmap.map[0] |=
					1U << fsal_mask2bit[i].fattr_bit;
				bmap.map[0] = 1U << fsal_mask2bit[i].mask;
			}
		}
	}

	memset(&args, 0, sizeof(args));
	args.attrs = (struct attrlist *)attrs;
	args.data = NULL;
	args.mounted_on_fileid = attrs->fileid;

	return nfs4_FSALattr_To_Fattr(&args, &bmap, data);
}

static GETATTR4resok *fs_fill_getattr_reply(nfs_resop4 *resop, char *blob,
					     size_t blob_sz)
{
	GETATTR4resok *a = &resop->nfs_resop4_u.opgetattr.GETATTR4res_u.resok4;

	a->obj_attributes.attrmask = empty_bitmap;
	a->obj_attributes.attr_vals.attrlist4_val = blob;
	a->obj_attributes.attr_vals.attrlist4_len = blob_sz;

	return a;
}

static void tc_update_sequence(nfs_argop4 *arg, nfs_resop4 *res, bool sent)
{
	SEQUENCE4args *sa;
	SEQUENCE4resok *sok;

	if (arg->argop != NFS4_OP_SEQUENCE) {
		return;
	}
	if (sent && res->nfs_resop4_u.opsequence.sr_status == NFS4_OK) {
		sok = &res->nfs_resop4_u.opsequence.SEQUENCE4res_u.sr_resok4;
		free_session_slot(sess_slot_tbl, sok->sr_slotid,
				  sok->sr_highest_slotid,
				  sok->sr_target_highest_slotid, sent);
	} else {
		sa = &arg->nfs_argop4_u.opsequence;
		free_session_slot(sess_slot_tbl, sa->sa_slotid,
				  sa->sa_highest_slotid, sa->sa_highest_slotid,
				  false);
	}
	slot_allocated = false;
}

static inline void tc_save_path(slice_t path)
{
        buf_t buf = {
                .data = tc_saved_path,
                .size = 0,
                .capacity = PATH_MAX,
        };

        buf_append_slice(&buf, path);
        buf_append_null(&buf);
}

static void tc_cleanup_compound(void *unused)
{
        opcnt = 0;
        while (tc_bufcnt) {
                free(tc_bufs[--tc_bufcnt]);
        }
        tc_saved_path[0] = 0;
}

static void tc_pthread_init(void)
{
	if (pthread_key_create(&tc_compound_resources, tc_cleanup_compound)) {
		NFS4_ERR("failed to install tc_cleanup_compound(): %s",
			 strerror(errno));
	}
}

static void tc_reset_compound(bool has_sequence)
{
	SEQUENCE4args *sa;

        if (pthread_once(&tc_once, tc_pthread_init)) {
                NFS4_ERR("pthread_once failed: %s", strerror(errno));
        }

        tc_cleanup_compound(NULL);

	/**
	 * We free the slot first, in case the previous compound allocated slot
	 * but failed before sending the RPC.
	 */
	if (slot_allocated) {
		assert(argoparray->argop == NFS4_OP_SEQUENCE);
		tc_update_sequence(argoparray, resoparray, false);
		slot_allocated = false;
	}

	if (has_sequence) {
		/* TODO: reuse sequence operation from previous compound? */
		argoparray->argop = NFS4_OP_SEQUENCE;
		sa = &argoparray->nfs_argop4_u.opsequence;
		memcpy(&sa->sa_sessionid, &fs_sessionid, NFS4_SESSIONID_SIZE);
		sa->sa_slotid = alloc_session_slot(
		    sess_slot_tbl, &sa->sa_sequenceid, &sa->sa_highest_slotid);
		slot_allocated = true;
		sa->sa_cachethis = false;
		++opcnt;
	}
}

static inline bool tc_has_enough_ops(int nops)
{
        return opcnt + nops <= MAX_NUM_OPS_PER_COMPOUND;
}

static char* tc_alloca(size_t bytes)
{
        if (tc_bufcnt == MAX_BUFS_PER_COMPOUND) {
                NFS4_ERR("Reached maximum number of buffers per compound: %d",
                         MAX_BUFS_PER_COMPOUND);
                return NULL;
        }
        char *b = malloc(bytes);
        if (!b) {
                NFS4_ERR("Out of memory when allocating buffer for compound");
                return NULL;
        }
        tc_bufs[tc_bufcnt++] = b;
        return b;
}

static buf_t* tc_alloca_buf(size_t bytes)
{
        return init_buf(tc_alloca(bytes + sizeof(buf_t)), bytes);
}

static int fs_got_rpc_reply(struct fs_rpc_io_context *ctx, int sock, int sz,
			     u_int xid)
{
	char *repbuf = ctx->recvbuf;
	int size;

	if (sz > ctx->recvbuf_sz)
		return -E2BIG;

	pthread_mutex_lock(&ctx->iolock);
	memcpy(repbuf, &xid, sizeof(xid));
	/*
	 * sz includes 4 bytes of xid which have been processed
	 * together with record mark - reduce the read to avoid
	 * gobbing up next record mark.
	 */
	repbuf += 4;
	ctx->ioresult = 4;
	sz -= 4;

	while (sz > 0) {
		/* TODO: handle timeouts - use poll(2) */
		int bc = read(sock, repbuf, sz);

		if (bc <= 0) {
			ctx->ioresult = -((bc < 0) ? errno : ETIMEDOUT);
			break;
		}
		repbuf += bc;
		ctx->ioresult += bc;
		sz -= bc;
	}
	ctx->iodone = 1;
	size = ctx->ioresult;
	pthread_cond_signal(&ctx->iowait);
	pthread_mutex_unlock(&ctx->iolock);
	return size;
}

static int fs_rpc_read_reply(int sock)
{
	struct {
		uint recmark;
		uint xid;
	} h;
	char *buf = (char *)&h;
	struct glist_head *c;
	char sink[256];
	int cnt = 0;

	while (cnt < 8) {
		int bc = read(sock, buf + cnt, 8 - cnt);
		if (bc < 0)
			return -errno;
		cnt += bc;
	}

	h.recmark = ntohl(h.recmark);
	/* TODO: check for final fragment */
	h.xid = ntohl(h.xid);

	LogDebug(COMPONENT_FSAL, "Recmark %x, xid %u\n", h.recmark, h.xid);
	h.recmark &= ~(1U << 31);

	pthread_mutex_lock(&listlock);
	glist_for_each(c, &rpc_calls) {
		struct fs_rpc_io_context *ctx =
		    container_of(c, struct fs_rpc_io_context, calls);

		if (ctx->rpc_xid == h.xid) {
			glist_del(c);
			pthread_mutex_unlock(&listlock);
			return fs_got_rpc_reply(ctx, sock, h.recmark, h.xid);
		}
	}
	pthread_mutex_unlock(&listlock);

	cnt = h.recmark - 4;
	LogDebug(COMPONENT_FSAL, "xid %u is not on the list, skip %d bytes\n",
		 h.xid, cnt);
	while (cnt > 0) {
		int rb = (cnt > sizeof(sink)) ? sizeof(sink) : cnt;

		rb = read(sock, sink, rb);
		if (rb <= 0)
			return -errno;
		cnt -= rb;
	}

	return 0;
}

static void fs_new_socket_ready(void)
{
	struct glist_head *nxt;
	struct glist_head *c;

	/* If there is anyone waiting for the socket then tell them
	 * it's ready */
	pthread_cond_broadcast(&sockless);

	/* If there are any outstanding calls then tell them to resend */
	glist_for_each_safe(c, nxt, &rpc_calls) {
		struct fs_rpc_io_context *ctx =
		    container_of(c, struct fs_rpc_io_context, calls);

		glist_del(c);

		pthread_mutex_lock(&ctx->iolock);
		ctx->iodone = 1;
		ctx->ioresult = -EAGAIN;
		pthread_cond_signal(&ctx->iowait);
		pthread_mutex_unlock(&ctx->iolock);
	}
}

static int fs_connect(const kernfs_specific_initinfo_t *info,
		       struct sockaddr_in *dest)
{
	int sock;
	if (info->use_privileged_client_port) {
		int priv_port = 0;
		sock = rresvport(&priv_port);
		if (sock < 0)
			LogCrit(COMPONENT_FSAL,
				"Cannot create TCP socket on privileged port");
	} else {
		sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (sock < 0)
			LogCrit(COMPONENT_FSAL, "Cannot create TCP socket - %d",
				errno);
	}

	if (sock >= 0) {
		if (connect(sock, (struct sockaddr *)dest, sizeof(*dest)) < 0) {
			close(sock);
			sock = -1;
		} else {
			fs_new_socket_ready();
		}
	}
	return sock;
}

/*
 * NB! rpc_sock can be closed by the sending thread but it will not be
 *     changing its value. Only this function will change rpc_sock which
 *     means that it can look at the value without holding the lock.
 */
static void *fs_rpc_recv(void *arg)
{
	const kernfs_specific_initinfo_t *info = arg;
	struct sockaddr_in addr_rpc;
	struct sockaddr_in *info_sock = (struct sockaddr_in *)&info->srv_addr;
	char addr[INET_ADDRSTRLEN];
	struct pollfd pfd;
	int millisec = info->srv_timeout * 1000;

	memset(&addr_rpc, 0, sizeof(addr_rpc));
	addr_rpc.sin_family = AF_INET;
	addr_rpc.sin_port = info->srv_port;
	memcpy(&addr_rpc.sin_addr, &info_sock->sin_addr,
	       sizeof(struct in_addr));

	for (;;) {
		int nsleeps = 0;
		pthread_mutex_lock(&listlock);
		do {
			rpc_sock = fs_connect(info, &addr_rpc);
			if (rpc_sock < 0) {
				if (nsleeps == 0)
					LogCrit(COMPONENT_FSAL,
						"Cannot connect to server %s:%u",
						inet_ntop(AF_INET,
							  &addr_rpc.sin_addr,
							  addr,
							  sizeof(addr)),
						ntohs(info->srv_port));
				pthread_mutex_unlock(&listlock);
				sleep(info->retry_sleeptime);
				nsleeps++;
				pthread_mutex_lock(&listlock);
			} else {
				LogDebug(COMPONENT_FSAL,
					 "Connected after %d sleeps, "
					 "resending outstanding calls",
					 nsleeps);
			}
		} while (rpc_sock < 0);
		pthread_mutex_unlock(&listlock);

		pfd.fd = rpc_sock;
		pfd.events = POLLIN | POLLRDHUP;

		while (rpc_sock >= 0) {
			switch (poll(&pfd, 1, millisec)) {
			case 0:
				LogDebug(COMPONENT_FSAL,
					 "Timeout, wait again...");
				continue;

			case -1:
				break;

			default:
				if (pfd.revents & POLLRDHUP) {
					LogEvent(COMPONENT_FSAL,
						 "Other end has closed "
						 "connection, reconnecting...");
				} else if (pfd.revents & POLLNVAL) {
					LogEvent(COMPONENT_FSAL,
						 "Socket is closed");
				} else {
					if (fs_rpc_read_reply(rpc_sock) >= 0)
						continue;
				}
				break;
			}

			pthread_mutex_lock(&listlock);
			close(rpc_sock);
			rpc_sock = -1;
			pthread_mutex_unlock(&listlock);
		}
	}

	return NULL;
}

static enum clnt_stat fs_process_reply(struct fs_rpc_io_context *ctx,
					COMPOUND4res *res)
{
	enum clnt_stat rc = RPC_CANTRECV;
	struct timespec ts;

	pthread_mutex_lock(&ctx->iolock);
	ts.tv_sec = time(NULL) + 60;
	ts.tv_nsec = 0;

	while (!ctx->iodone) {
		int w = pthread_cond_timedwait(&ctx->iowait, &ctx->iolock, &ts);
		if (w == ETIMEDOUT) {
			pthread_mutex_unlock(&ctx->iolock);
			return RPC_TIMEDOUT;
		}
	}

	ctx->iodone = 0;
	pthread_mutex_unlock(&ctx->iolock);

	if (ctx->ioresult > 0) {
		struct rpc_msg reply;
		XDR x;

		memset(&reply, 0, sizeof(reply));
		reply.acpted_rply.ar_results.proc =
		    (xdrproc_t) xdr_COMPOUND4res;
		reply.acpted_rply.ar_results.where = (caddr_t) res;

		memset(&x, 0, sizeof(x));
		xdrmem_create(&x, ctx->recvbuf, ctx->ioresult, XDR_DECODE);

		/* macro is defined, GCC 4.7.2 ignoring */
		if (xdr_replymsg(&x, &reply)) {
			if (reply.rm_reply.rp_stat == MSG_ACCEPTED) {
				switch (reply.rm_reply.rp_acpt.ar_stat) {
				case SUCCESS:
					rc = RPC_SUCCESS;
					break;
				case PROG_UNAVAIL:
					rc = RPC_PROGUNAVAIL;
					break;
				case PROG_MISMATCH:
					rc = RPC_PROGVERSMISMATCH;
					break;
				case PROC_UNAVAIL:
					rc = RPC_PROCUNAVAIL;
					break;
				case GARBAGE_ARGS:
					rc = RPC_CANTDECODEARGS;
					break;
				case SYSTEM_ERR:
					rc = RPC_SYSTEMERROR;
					break;
				default:
					rc = RPC_FAILED;
					break;
				}
			} else {
				switch (reply.rm_reply.rp_rjct.rj_stat) {
				case RPC_MISMATCH:
					rc = RPC_VERSMISMATCH;
					break;
				case AUTH_ERROR:
					rc = RPC_AUTHERROR;
					break;
				default:
					rc = RPC_FAILED;
					break;
				}
			}
		} else {
			rc = RPC_CANTDECODERES;
		}

		reply.acpted_rply.ar_results.proc = (xdrproc_t) xdr_void;
		reply.acpted_rply.ar_results.where = NULL;

		xdr_free((xdrproc_t) xdr_replymsg, &reply);
	}
	return rc;
}

static void fs_rpc_need_sock(void)
{
	pthread_mutex_lock(&listlock);
	while (rpc_sock < 0)
		pthread_cond_wait(&sockless, &listlock);
	pthread_mutex_unlock(&listlock);
}

static int fs_rpc_renewer_wait(int timeout)
{
	struct timespec ts;
	int rc;

	pthread_mutex_lock(&listlock);
	ts.tv_sec = time(NULL) + timeout;
	ts.tv_nsec = 0;

	rc = pthread_cond_timedwait(&sockless, &listlock, &ts);
	pthread_mutex_unlock(&listlock);
	return (rc == ETIMEDOUT);
}

static int fs_compoundv4_call(struct fs_rpc_io_context *pcontext,
			       const struct user_cred *cred,
			       COMPOUND4args *args, COMPOUND4res *res)
{
	XDR x;
	struct rpc_msg rmsg;
	AUTH *au;
	enum clnt_stat rc;

	pthread_mutex_lock(&listlock);
	rmsg.rm_xid = rpc_xid++;
	pthread_mutex_unlock(&listlock);
	rmsg.rm_direction = CALL;

	rmsg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
	rmsg.rm_call.cb_prog = pcontext->nfs_prog;
	rmsg.rm_call.cb_vers = FSAL_PROXY_NFS_V4;
	rmsg.rm_call.cb_proc = NFSPROC4_COMPOUND;

	if (cred) {
		au = authunix_create(fs_hostname, cred->caller_uid,
				     cred->caller_gid, cred->caller_glen,
				     cred->caller_garray);
	} else {
		au = authunix_create_default();
	}
	if (au == NULL)
		return RPC_AUTHERROR;

	rmsg.rm_call.cb_cred = au->ah_cred;
	rmsg.rm_call.cb_verf = au->ah_verf;

	memset(&x, 0, sizeof(x));
	xdrmem_create(&x, pcontext->sendbuf + 4, pcontext->sendbuf_sz,
		      XDR_ENCODE);
	if (xdr_callmsg(&x, &rmsg) && xdr_COMPOUND4args(&x, args)) {
		u_int pos = xdr_getpos(&x);
		u_int recmark = ntohl(pos | (1U << 31));
		int first_try = 1;

		pcontext->rpc_xid = rmsg.rm_xid;

		memcpy(pcontext->sendbuf, &recmark, sizeof(recmark));
		pos += 4;

		do {
			int bc = 0;
			char *buf = pcontext->sendbuf;
			LogDebug(COMPONENT_FSAL, "%ssend XID %u with %d bytes",
				 (first_try ? "First attempt to " : "Re"),
				 rmsg.rm_xid, pos);
			pthread_mutex_lock(&listlock);
			while (bc < pos) {
				int wc = write(rpc_sock, buf, pos - bc);
				if (wc <= 0) {
					close(rpc_sock);
					break;
				}
				bc += wc;
				buf += wc;
			}

			if (bc == pos) {
				if (first_try) {
					glist_add_tail(&rpc_calls,
						       &pcontext->calls);
					first_try = 0;
				}
			} else {
				if (!first_try)
					glist_del(&pcontext->calls);
			}
			pthread_mutex_unlock(&listlock);

			if (bc == pos)
				rc = fs_process_reply(pcontext, res);
			else
				rc = RPC_CANTSEND;
		} while (rc == RPC_TIMEDOUT);
	} else {
		rc = RPC_CANTENCODEARGS;
	}
	if (au)
		auth_destroy(au);
	return rc;
}

/**
 * Make the RPC call of the NFS request.  Note the difference of failure of RPC
 * and failure of NFS.  If "nfsstat" is NULL, the return value is the status of
 * the whole call (both RPC and NFS).  If "nfsstat" is not NULL, the return
 * value is the status of RPC call and "nfsstat" is the status of the NFS
 * request.
 */
static int fs_compoundv4_execute(const char *caller,
				 const struct user_cred *creds,
				 int *nfsstat)
{
	enum clnt_stat rc;
	struct fs_rpc_io_context *ctx;
	COMPOUND4args arg = {
		.minorversion = 1,
		.argarray.argarray_val = argoparray,
		.argarray.argarray_len = opcnt
	};
	COMPOUND4res res = {
		.resarray.resarray_val = resoparray,
		.resarray.resarray_len = opcnt
	};
        TC_DECLARE_COUNTER(rpc);

	pthread_mutex_lock(&context_lock);
	while (glist_empty(&free_contexts))
		pthread_cond_wait(&need_context, &context_lock);
	ctx =
	    glist_first_entry(&free_contexts, struct fs_rpc_io_context, calls);
	glist_del(&ctx->calls);
	pthread_mutex_unlock(&context_lock);

        TC_START_COUNTER(rpc);

	do {
		rc = fs_compoundv4_call(ctx, creds, &arg, &res);
		if (rc != RPC_SUCCESS)
			NFS4_DEBUG("RPC by %s failed with %d", caller, rc);
		if (rc == RPC_CANTSEND)
			fs_rpc_need_sock();
	} while ((rc == RPC_CANTRECV && (ctx->ioresult == -EAGAIN))
		 || (rc == RPC_CANTSEND));

	TC_STOP_COUNTER(rpc, opcnt, rc == RPC_SUCCESS);

	pthread_mutex_lock(&context_lock);
	pthread_cond_signal(&need_context);
	glist_add(&free_contexts, &ctx->calls);
	pthread_mutex_unlock(&context_lock);

	if (rc == RPC_SUCCESS) {
               if (nfsstat != NULL) {
                        *nfsstat = nfsstat4_to_errno(res.status);
               } else {
                       rc = res.status;
               }
        }
        tc_update_sequence(argoparray, resoparray, rc == RPC_SUCCESS);
	return rc;
}

#define fs_nfsv4_call(creds, st) \
	fs_compoundv4_execute(__func__, creds, st)

void fs_get_clientid(clientid4 *ret)
{
	pthread_mutex_lock(&fs_clientid_mutex);
	*ret = fs_clientid;
	pthread_mutex_unlock(&fs_clientid_mutex);
}

void tc_get_clientid(clientid4 *ret)
{
	pthread_mutex_lock(&fs_clientid_mutex);
	*ret = tc_clientid;
	pthread_mutex_unlock(&fs_clientid_mutex);
}

static int fs_setclientid(clientid4 *resultclientid, uint32_t *lease_time)
{
	int rc;
	nfs_client_id4 nfsclientid;
	cb_client4 cbkern;
	char clientid_name[MAXNAMLEN + 1];
	SETCLIENTID4resok *sok;
	struct sockaddr_in sin;
	struct netbuf nb;
	struct netconfig *ncp;
	socklen_t slen = sizeof(sin);
	char addrbuf[sizeof("255.255.255.255")];
	char *buf;

	LogEvent(COMPONENT_FSAL,
		 "Negotiating a new ClientId with the remote server");

	if (getsockname(rpc_sock, &sin, &slen))
		return -errno;

	snprintf(clientid_name, MAXNAMLEN, "%s(%d) - GANESHA NFSv4 Proxy",
		 inet_ntop(AF_INET, &sin.sin_addr, addrbuf, sizeof(addrbuf)),
		 getpid());
	nfsclientid.id.id_len = strlen(clientid_name);
	nfsclientid.id.id_val = clientid_name;
	if (sizeof(ServerBootTime.tv_sec) == NFS4_VERIFIER_SIZE)
		memcpy(&nfsclientid.verifier, &ServerBootTime.tv_sec,
		       sizeof(nfsclientid.verifier));
	else
		snprintf(nfsclientid.verifier, NFS4_VERIFIER_SIZE, "%08x",
			 (int)ServerBootTime.tv_sec);

	ncp = getnetconfigent("tcp");
	nb.len = sizeof(struct sockaddr_in);
	nb.maxlen = nb.len;
	nb.buf = (char *) &sin;
	buf = taddr2uaddr(ncp, &nb);
	cbkern.cb_program = 0x40000000;
	cbkern.cb_location.r_netid = "tcp";
	cbkern.cb_location.r_addr = buf;
	//cbkern.cb_location.r_addr = "127.0.0.1";

	tc_reset_compound(false);
	sok = &resoparray->nfs_resop4_u.opsetclientid.SETCLIENTID4res_u.resok4;
	argoparray->argop = NFS4_OP_SETCLIENTID;
	argoparray->nfs_argop4_u.opsetclientid.client = nfsclientid;
	argoparray->nfs_argop4_u.opsetclientid.callback = cbkern;
	argoparray->nfs_argop4_u.opsetclientid.callback_ident = 1;
	++opcnt;

	rc = fs_nfsv4_call(NULL, NULL);
	if (rc != NFS4_OK)
		return -1;

	tc_reset_compound(false);
	argoparray->argop = NFS4_OP_SETCLIENTID_CONFIRM;
	argoparray->nfs_argop4_u.opsetclientid_confirm.clientid = sok->clientid;
	memcpy(
	    argoparray->nfs_argop4_u.opsetclientid_confirm.setclientid_confirm,
	    sok->setclientid_confirm, NFS4_VERIFIER_SIZE);
	++opcnt;

	rc = fs_nfsv4_call(NULL, NULL);
	if (rc != NFS4_OK)
		return -1;

	/* Keep the confirmed client id */
	*resultclientid = argoparray->nfs_argop4_u.opsetclientid_confirm.clientid;

	/* Get the lease time */
/*
	opcnt = 0;
	COMPOUNDV4_ARG_ADD_OP_PUTROOTFH(opcnt, arg);
	fs_fill_getattr_reply(res + opcnt, (char *)lease_time,
			       sizeof(*lease_time));
	COMPOUNDV4_ARG_ADD_OP_GETATTR(opcnt, arg, lease_bits);

	rc = fs_compoundv4_execute(__func__, NULL, opcnt, arg, res);
	if (rc != NFS4_OK)
		*lease_time = 60;
	else
		*lease_time = ntohl(*lease_time);
*/
	*lease_time = 60;

	return 0;
}

static fsal_status_t fs_destroy_session()
{
        int rc;

        tc_reset_compound(false);

        argoparray->argop = NFS4_OP_DESTROY_SESSION;
        memcpy(&argoparray->nfs_argop4_u.opdestroy_session.dsa_sessionid,
               &fs_sessionid, NFS4_SESSIONID_SIZE);
        opcnt++;

        rc = fs_nfsv4_call(NULL, NULL);
        if (rc != NFS4_OK) {
		return nfsstat4_to_fsal(rc);
	}

	del_session_slot_table(&sess_slot_tbl);

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static int fs_reclaim_complete()
{
        int rc;

        tc_reset_compound(true);

	argoparray[opcnt].argop = NFS4_OP_RECLAIM_COMPLETE;
	argoparray[opcnt].nfs_argop4_u.opreclaim_complete.rca_one_fs = false;
	opcnt++;

        rc = fs_nfsv4_call(NULL, NULL);
        if (rc != NFS4_OK) {
		return rc;
	}

	return 0;
}

static int fs_create_session()
{
	int rc;
	char machname[MAXHOSTNAMELEN + 1];
	client_owner4 nfsclientowner;
	uint32_t eia_flags = 0;
	channel_attrs4 csa_fore_chan_attrs = { .ca_headerpadsize = 0,
					       .ca_maxrequestsize = 1049620,
					       .ca_maxresponsesize = 1049480,
					       .ca_maxresponsesize_cached =
						   4616,
					       .ca_maxoperations =
						   MAX_NUM_OPS_PER_COMPOUND,
					       .ca_maxrequests = 128 };

	channel_attrs4 csa_back_chan_attrs = { .ca_headerpadsize = 0,
					       .ca_maxrequestsize = 4096,
					       .ca_maxresponsesize = 4096,
					       .ca_maxresponsesize_cached = 0,
					       .ca_maxoperations = 2,
					       .ca_maxrequests = 1 };
	char clientid_name[MAXNAMLEN + 1];
	struct timespec now;
	callback_sec_parms4 csa_sec_parms_val;
        EXCHANGE_ID4args *eia;
        EXCHANGE_ID4resok *eir;
        CREATE_SESSION4args *csa;
        CREATE_SESSION4resok *csr;
	uint32_t csa_flags = 0;
        struct sockaddr_in sin;
        char server_major_id_buf[NFS4_OPAQUE_LIMIT];
        char server_scope_buf[NFS4_OPAQUE_LIMIT];
        nfs_impl_id4 server_impl_id;
        struct netbuf nb;
        struct netconfig *ncp;
        socklen_t slen = sizeof(sin);
        char addrbuf[sizeof("255.255.255.255")];
        char *buf;

        LogEvent(COMPONENT_FSAL,
                 "Negotiating a new v4.1 session with the remote server");

        if (getsockname(rpc_sock, &sin, &slen))
                return -errno;

        snprintf(clientid_name, MAXNAMLEN, "%s(%d) - GANESHA NFSv4 Proxy",
                 inet_ntop(AF_INET, &sin.sin_addr, addrbuf, sizeof(addrbuf)),
                 getpid());
	nfsclientowner.co_ownerid.co_ownerid_len = strlen(clientid_name);
	nfsclientowner.co_ownerid.co_ownerid_val = clientid_name;
	if (sizeof(ServerBootTime.tv_sec) == NFS4_VERIFIER_SIZE)
                memcpy(&nfsclientowner.co_verifier, &ServerBootTime.tv_sec,
                       sizeof(nfsclientowner.co_verifier));
        else
                snprintf(nfsclientowner.co_verifier, NFS4_VERIFIER_SIZE, "%08x",
                         (int)ServerBootTime.tv_sec);

	eia_flags |=
	    (EXCHGID4_FLAG_SUPP_MOVED_REFER | EXCHGID4_FLAG_BIND_PRINC_STATEID);

        tc_reset_compound(false);

	eia = &argoparray[opcnt].nfs_argop4_u.opexchange_id;
	argoparray[opcnt++].argop = NFS4_OP_EXCHANGE_ID;
	eia->eia_clientowner = nfsclientowner;
	eia->eia_flags = eia_flags;
	eia->eia_state_protect.spa_how = SP4_NONE;
	eia->eia_client_impl_id.eia_client_impl_id_len = 0;

	eir = &resoparray->nfs_resop4_u.opexchange_id.EXCHANGE_ID4res_u
		   .eir_resok4;
	eir->eir_server_owner.so_major_id.so_major_id_val = server_major_id_buf;
	eir->eir_server_scope.eir_server_scope_val = server_scope_buf;
	eir->eir_server_impl_id.eir_server_impl_id_val = &server_impl_id;

	rc = fs_nfsv4_call(NULL, NULL);
	if (rc != NFS4_OK) {
		LogEvent(COMPONENT_FSAL, "exchange id failure: %d", rc);
		return -1;
	}

	memcpy(&tc_clientid, &eir->eir_clientid, sizeof(clientid4));

	if (gethostname(machname, sizeof(machname)) == -1) {
		rpc_createerr.cf_error.re_errno = errno;
		return -1;
	}
	machname[sizeof(machname) - 1] = 0;
	(void)clock_gettime(CLOCK_MONOTONIC_FAST, &now);

	csa_sec_parms_val.cb_secflavor = AUTH_UNIX;
	csa_sec_parms_val.callback_sec_parms4_u.cbsp_sys_cred.aup_time = now.tv_sec;
	csa_sec_parms_val.callback_sec_parms4_u.cbsp_sys_cred.aup_machname = machname;
	csa_sec_parms_val.callback_sec_parms4_u.cbsp_sys_cred.aup_uid = 0;
	csa_sec_parms_val.callback_sec_parms4_u.cbsp_sys_cred.aup_gid = 0;
	csa_sec_parms_val.callback_sec_parms4_u.cbsp_sys_cred.aup_len = 0;

	csa_flags |= CREATE_SESSION4_FLAG_PERSIST;

        tc_reset_compound(false);

	csa = &argoparray[opcnt].nfs_argop4_u.opcreate_session;
	argoparray[opcnt++].argop = NFS4_OP_CREATE_SESSION;
	csa->csa_clientid = eir->eir_clientid;
	csa->csa_sequence = eir->eir_sequenceid;
	csa->csa_flags = 1;
	csa->csa_fore_chan_attrs = csa_fore_chan_attrs;
	csa->csa_back_chan_attrs = csa_back_chan_attrs;
	csa->csa_cb_program = 0x40000000;
	csa->csa_sec_parms.csa_sec_parms_val = &csa_sec_parms_val;
	csa->csa_sec_parms.csa_sec_parms_len = 1;

	LogEvent(COMPONENT_FSAL, "create session called");
	rc = fs_nfsv4_call(NULL, NULL);
	if (rc != NFS4_OK) {
		LogEvent(COMPONENT_FSAL, "create session failed: %d", rc);
		return -1;
	}

	csr = &resoparray->nfs_resop4_u.opcreate_session.CREATE_SESSION4res_u
		   .csr_resok4;
	memcpy(&fs_sessionid, csr->csr_sessionid, NFS4_SESSIONID_SIZE);
	fs_sequenceid = csr->csr_sequence;

        if (sess_slot_tbl) {
                NFS4_WARN("currently only one session is supported\n");
                del_session_slot_table(&sess_slot_tbl);
        }
        sess_slot_tbl = new_session_slot_table();
        if (!sess_slot_tbl) {
                NFS4_ERR("cannot create session slot table");
                return -ENOMEM;
        }

	//fs_destroy_session();
	rc = fs_reclaim_complete();
        if (rc != 0) {
		NFS4_ERR("fs_reclaim_complete() failed: %d", rc);
		return -rc;
        }

	return 0;
}

static void *fs_clientid_renewer(void *Arg)
{
	int rc;
	int needed = 1;
	uint32_t lease_time = 60;

	while (1) {
		clientid4 newcid = 0;

		if (!needed && fs_rpc_renewer_wait(lease_time - 5)) {
			/* Simply renew the client id you've got */
			LogDebug(COMPONENT_FSAL, "Renewing client id %lx",
				 fs_clientid);
                        tc_reset_compound(false);
			argoparray->argop = NFS4_OP_RENEW;
			argoparray->nfs_argop4_u.oprenew.clientid = fs_clientid;
                        ++opcnt;
			rc = fs_nfsv4_call(NULL, NULL);
			if (rc == NFS4_OK) {
				LogDebug(COMPONENT_FSAL,
					 "Renewed client id %lx", fs_clientid);
				continue;
			}
		}

		/* We've either failed to renew or rpc socket has been
		 * reconnected and we need new client id */
		LogDebug(COMPONENT_FSAL, "Need %d new client id", needed);
		fs_rpc_need_sock();
		needed = fs_setclientid(&newcid, &lease_time);
		if (!needed) {
			pthread_mutex_lock(&fs_clientid_mutex);
			fs_clientid = newcid;
			pthread_mutex_unlock(&fs_clientid_mutex);
		}
	}
	return NULL;
}

void free_io_contexts(void)
{
	struct glist_head *cur, *n;
	glist_for_each_safe(cur, n, &free_contexts) {
		struct fs_rpc_io_context *c =
		    container_of(cur, struct fs_rpc_io_context, calls);
		glist_del(cur);
		gsh_free(c);
	}
}

int fs_init_rpc(const struct fs_fsal_module *pm)
{
	int rc;
	int i = 16;

	glist_init(&rpc_calls);
	glist_init(&free_contexts);

/**
 * @todo this lock is not really necessary so long as we can
 *       only do one export at a time.  This is a reminder that
 *       there is work to do to get this fnctn to truely be
 *       per export.
 */
	pthread_mutex_lock(&listlock);
	if (rpc_xid == 0)
		rpc_xid = getpid() ^ time(NULL);
	pthread_mutex_unlock(&listlock);
	if (gethostname(fs_hostname, sizeof(fs_hostname)))
		strncpy(fs_hostname, "NFS-TC", sizeof(fs_hostname));

	for (i = 16; i > 0; i--) {
		struct fs_rpc_io_context *c =
		    gsh_calloc(1, sizeof(*c) + pm->special.srv_sendsize +
			       pm->special.srv_recvsize);
		if (!c) {
			free_io_contexts();
			return ENOMEM;
		}
		pthread_mutex_init(&c->iolock, NULL);
		pthread_cond_init(&c->iowait, NULL);
		c->nfs_prog = pm->special.srv_prognum;
		c->sendbuf_sz = pm->special.srv_sendsize;
		c->recvbuf_sz = pm->special.srv_recvsize;
		c->sendbuf = (char *)(c + 1);
		c->recvbuf = c->sendbuf + c->sendbuf_sz;

		glist_add(&free_contexts, &c->calls);
	}

	rc = pthread_create(&fs_recv_thread, NULL, fs_rpc_recv,
			    (void *)&pm->special);
	if (rc) {
		LogCrit(COMPONENT_FSAL,
			"Cannot create kern rpc receiver thread - %s",
			strerror(rc));
		free_io_contexts();
		return rc;
	}

        /*
	rc = pthread_create(&fs_renewer_thread, NULL, fs_clientid_renewer,
			    NULL);
	if (rc) {
		LogCrit(COMPONENT_FSAL,
			"Cannot create kern clientid renewer thread - %s",
			strerror(rc));
		free_io_contexts();
	}
        */

	fs_rpc_need_sock();
	rc = fs_create_session();
	if (rc) {
		NFS4_ERR("Cannot create session - %s", strerror(rc));
		free_io_contexts();
	}

	return rc;
}

static fsal_status_t fs_make_object(struct fsal_export *export,
				     fattr4 *obj_attributes,
				     const nfs_fh4 *fh,
				     struct fsal_obj_handle **handle)
{
	struct attrlist attributes = {0};
	struct fs_obj_handle *fs_hdl;

	memset(&attributes, 0, sizeof(struct attrlist));

	if (nfs4_Fattr_To_FSAL_attr(&attributes, obj_attributes, NULL) !=
	    NFS4_OK)
		return fsalstat(ERR_FSAL_INVAL, 0);

	fs_hdl = fs_alloc_handle(export, fh, &attributes);
	if (fs_hdl == NULL)
		return fsalstat(ERR_FSAL_FAULT, 0);
	*handle = &fs_hdl->obj;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static fsal_status_t fs_root_lookup_impl(struct fsal_export *export,
		const struct user_cred *cred,
		struct fsal_obj_handle **handle)
{
	int rc;
	GETATTR4resok *atok;
	GETFH4resok *fhok;
	char fattr_blob[FATTR_BLOB_SZ];
	char padfilehandle[NFS4_FHSIZE];

	if (!handle)
		return fsalstat(ERR_FSAL_INVAL, 0);

        tc_reset_compound(true);

	COMPOUNDV4_ARG_ADD_OP_PUTROOTFH(opcnt, argoparray);

	fhok = &resoparray[opcnt].nfs_resop4_u.opgetfh.GETFH4res_u.resok4;
	COMPOUNDV4_ARG_ADD_OP_GETFH(opcnt, argoparray);

	atok =
		fs_fill_getattr_reply(resoparray + opcnt, fattr_blob,
				sizeof(fattr_blob));

	COMPOUNDV4_ARG_ADD_OP_GETATTR(opcnt, argoparray, fs_bitmap_getattr);

	fhok->object.nfs_fh4_val = (char *)padfilehandle;
	fhok->object.nfs_fh4_len = sizeof(padfilehandle);

	rc = fs_nfsv4_call(cred, NULL);
	if (rc != NFS4_OK)
		return nfsstat4_to_fsal(rc);

	return fs_make_object(export, &atok->obj_attributes, &fhok->object,
			handle);
}

/*
 * NULL parent pointer is only used by lookup_path when it starts
 * from the root handle and has its own export pointer, everybody
 * else is supposed to provide a real parent pointer and matching
 * export
 */
static fsal_status_t fs_lookup_impl(struct fsal_obj_handle *parent,
				     struct fsal_export *export,
				     const struct user_cred *cred,
				     const char *path,
				     struct fsal_obj_handle **handle)
{
	int rc;
	GETATTR4resok *atok;
	GETFH4resok *fhok;
	char fattr_blob[FATTR_BLOB_SZ];
	char padfilehandle[NFS4_FHSIZE];

	LogDebug(COMPONENT_FSAL, "lookup_impl() called\n");

	if (!handle)
		return fsalstat(ERR_FSAL_INVAL, 0);

        tc_reset_compound(true);

	if (!parent) {
		COMPOUNDV4_ARG_ADD_OP_PUTROOTFH(opcnt, argoparray);
	} else {
		struct fs_obj_handle *fs_obj =
		    container_of(parent, struct fs_obj_handle, obj);
		switch (parent->type) {
		case DIRECTORY:
			break;
		default:
			return fsalstat(ERR_FSAL_NOTDIR, 0);
		}

		COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, fs_obj->fh4);
	}

	if (path) {
		if (!strcmp(path, ".")) {
			if (!parent)
				return fsalstat(ERR_FSAL_FAULT, 0);
		} else if (!strcmp(path, "..")) {
			if (!parent)
				return fsalstat(ERR_FSAL_FAULT, 0);
			COMPOUNDV4_ARG_ADD_OP_LOOKUPP(opcnt, argoparray);
		} else {
			COMPOUNDV4_ARG_ADD_OP_LOOKUP(opcnt, argoparray, path);
		}
	}

	fhok = &resoparray[opcnt].nfs_resop4_u.opgetfh.GETFH4res_u.resok4;
	COMPOUNDV4_ARG_ADD_OP_GETFH(opcnt, argoparray);

	atok =
	    fs_fill_getattr_reply(resoparray + opcnt, fattr_blob,
				   sizeof(fattr_blob));

	COMPOUNDV4_ARG_ADD_OP_GETATTR(opcnt, argoparray, fs_bitmap_getattr);

	fhok->object.nfs_fh4_val = (char *)padfilehandle;
	fhok->object.nfs_fh4_len = sizeof(padfilehandle);

	rc = fs_nfsv4_call(cred, NULL);
	if (rc != NFS4_OK)
		return nfsstat4_to_fsal(rc);

	return fs_make_object(export, &atok->obj_attributes, &fhok->object,
			      handle);
}

static fsal_status_t fs_lookup(struct fsal_obj_handle *parent,
				const char *path,
				struct fsal_obj_handle **handle)
{
	LogDebug(COMPONENT_FSAL, "fs_lookup() for nonroot reached\n");
	return fs_lookup_impl(parent, op_ctx->fsal_export,
			       op_ctx->creds, path, handle);
}

static fsal_status_t fs_root_lookup(struct fsal_obj_handle **handle)
{
	return fs_root_lookup_impl(op_ctx->fsal_export,
			op_ctx->creds, handle);
}

static fsal_status_t fs_do_close(const struct user_cred *creds,
				  const nfs_fh4 *fh4, stateid4 *sid,
				  struct fsal_export *exp)
{
	int rc;

	/* Check if this was a "stateless" open,
	 * then nothing is to be done at close */
	if (is_special_stateid(sid))
		return fsalstat(ERR_FSAL_NO_ERROR, 0);

        tc_reset_compound(true);

	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, *fh4);
	COMPOUNDV4_ARG_ADD_OP_CLOSE(opcnt, argoparray, sid);

	rc = fs_nfsv4_call(creds, NULL);
	if (rc != NFS4_OK)
		return nfsstat4_to_fsal(rc);
	sid->seqid++;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static inline void copy_stateid4(stateid4 *dstid, const stateid4 *srcid)
{
        dstid->seqid = srcid->seqid;
        memmove(dstid->other, srcid->other, 12);
}

static fsal_status_t fs_open_confirm(const struct user_cred *cred,
				      const nfs_fh4 *fh4, stateid4 *stateid,
				      struct fsal_export *export)
{
	int rc;
	nfs_argop4 *op;
	OPEN_CONFIRM4resok *conok;

        tc_reset_compound(true);

	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, *fh4);

	conok =
	    &resoparray[opcnt].nfs_resop4_u.opopen_confirm.OPEN_CONFIRM4res_u.
	    resok4;

	op = argoparray + opcnt++;
	op->argop = NFS4_OP_OPEN_CONFIRM;
	copy_stateid4(&op->nfs_argop4_u.opopen_confirm.open_stateid, stateid);
	/*
	 * According to RFC3530 14.2.18:
	 *	"The sequence id passed to the OPEN_CONFIRM must be 1 (one)
	 *	greater than the seqid passed to the OPEN operation from which
	 *	the open_confirm value was obtained."
	 * As seqid is hardcoded as 0 in COMPOUNDV4_ARG_ADD_OP_OPEN_CREATE, we
	 * use 1 here.
	 */
	op->nfs_argop4_u.opopen_confirm.seqid = 1;

	rc = fs_nfsv4_call(cred, NULL);
	if (rc != NFS4_OK)
		return nfsstat4_to_fsal(rc);

	copy_stateid4(stateid, &conok->open_stateid);
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/* TODO: make this per-export */
static uint64_t fcnt;

static inline unsigned tc_new_state_owner(buf_t *pbuf)
{
	return buf_appendf(buf_reset(pbuf), "TC-State: pid=%d %" PRIu64,
			   getpid(), atomic_inc_uint64_t(&fcnt));
}

static inline unsigned tc_create_state_owner(char owner_val[128])
{
	int n =  snprintf(owner_val, 128,
			"TC-State: pid=%d %" PRIu64, getpid(),
			atomic_inc_uint64_t(&fcnt));
        NFS4_DEBUG("state_owner: %s; len: %d", owner_val, n);
        return n;
}

static fsal_status_t fs_create(struct fsal_obj_handle *dir_hdl,
				const char *name, struct attrlist *attrib,
				struct fsal_obj_handle **handle)
{
	int rc;
	fattr4 input_attr;
	char padfilehandle[NFS4_FHSIZE];
	char fattr_blob[FATTR_BLOB_SZ];
	char owner_val[128];
	unsigned int owner_len = 0;
	GETFH4resok *fhok;
	GETATTR4resok *atok;
	OPEN4resok *opok;
	struct fs_obj_handle *ph;
	fsal_status_t st;
	clientid4 cid;

        owner_len = tc_create_state_owner(owner_val);

	attrib->mask &= ATTR_MODE | ATTR_OWNER | ATTR_GROUP;
	if (fs_fsalattr_to_fattr4(attrib, &input_attr) == -1)
		return fsalstat(ERR_FSAL_INVAL, -1);

        tc_reset_compound(true);

	ph = container_of(dir_hdl, struct fs_obj_handle, obj);
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);

	opok = &resoparray[opcnt].nfs_resop4_u.opopen.OPEN4res_u.resok4;
	opok->attrset = empty_bitmap;
	tc_get_clientid(&cid);
	COMPOUNDV4_ARG_ADD_OP_OPEN_CREATE(opcnt, argoparray, (char *)name,
					  input_attr, cid, owner_val,
					  owner_len);

	fhok = &resoparray[opcnt].nfs_resop4_u.opgetfh.GETFH4res_u.resok4;
	fhok->object.nfs_fh4_val = padfilehandle;
	fhok->object.nfs_fh4_len = sizeof(padfilehandle);
	COMPOUNDV4_ARG_ADD_OP_GETFH(opcnt, argoparray);

	atok =
	    fs_fill_getattr_reply(resoparray + opcnt, fattr_blob,
				   sizeof(fattr_blob));
	COMPOUNDV4_ARG_ADD_OP_GETATTR(opcnt, argoparray, fs_bitmap_getattr);

	rc = fs_nfsv4_call(op_ctx->creds, NULL);
	nfs4_Fattr_Free(&input_attr);
	if (rc != NFS4_OK)
		return nfsstat4_to_fsal(rc);

	/* See if a OPEN_CONFIRM is required */
	if (opok->rflags & OPEN4_RESULT_CONFIRM) {
		st = fs_open_confirm(op_ctx->creds, &fhok->object,
				      &opok->stateid,
				      op_ctx->fsal_export);
		if (FSAL_IS_ERROR(st)) {
			LogDebug(COMPONENT_FSAL,
				"fs_open_confirm failed: status %d", st);
			return st;
		}
	}

	/* The created file is still opened, to preserve the correct
	 * seqid for later use, we close it */
	st = fs_do_close(op_ctx->creds, &fhok->object, &opok->stateid,
			  op_ctx->fsal_export);
	if (FSAL_IS_ERROR(st))
		return st;
	st = fs_make_object(op_ctx->fsal_export,
			     &atok->obj_attributes,
			     &fhok->object, handle);
	if (FSAL_IS_ERROR(st))
		return st;
	*attrib = (*handle)->attributes;
	return st;
}

static fsal_status_t fs_read_state(const nfs_fh4 *fh4, const nfs_fh4 *fh4_1,
				   uint64_t offset, size_t buffer_size,
				   void *buffer, size_t *read_amount,
				   bool *end_of_file, stateid4 *sid,
				   stateid4 *sid1)
{
	int rc;
	/*struct fs_obj_handle *ph;*/
	READ4resok *rok;

	LogDebug(COMPONENT_FSAL, "fs_read_state called \n");

	if (!buffer_size) {
		*read_amount = 0;
		*end_of_file = false;
		return fsalstat(ERR_FSAL_NO_ERROR, 0);
	}
	/*ph = container_of(obj_hdl, struct fs_obj_handle, obj);*/
	#if 0
        if ((ph->openflags & (FSAL_O_RDONLY | FSAL_O_RDWR)) == 0)
                return fsalstat(ERR_FSAL_FILE_OPEN, EBADF);
#endif

	if (buffer_size >
	    op_ctx->fsal_export->ops->fs_maxread(op_ctx->fsal_export))
		buffer_size =
		    op_ctx->fsal_export->ops->fs_maxread(op_ctx->fsal_export);

        tc_reset_compound(true);

	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, *fh4);
	rok = &resoparray[opcnt].nfs_resop4_u.opread.READ4res_u.resok4;
	rok->data.data_val = buffer;
	rok->data.data_len = buffer_size;
	/*COMPOUNDV4_ARG_ADD_OP_READ_STATE(opcnt, argoparray, offset,
	 * buffer_size, sid);*/
	COMPOUNDV4_ARG_ADD_OP_READ(opcnt, argoparray, offset, buffer_size);
	rok = &resoparray[opcnt].nfs_resop4_u.opread.READ4res_u.resok4;
	rok->data.data_val = buffer;
	rok->data.data_len = buffer_size;
	COMPOUNDV4_ARG_ADD_OP_READ_STATE(
	    opcnt, argoparray, offset + buffer_size, buffer_size, sid);

	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, *fh4_1);
	rok = &resoparray[opcnt].nfs_resop4_u.opread.READ4res_u.resok4;
	rok->data.data_val = buffer;
	rok->data.data_len = buffer_size;
	COMPOUNDV4_ARG_ADD_OP_READ_STATE(opcnt, argoparray, offset, buffer_size,
					 sid1);
	rok = &resoparray[opcnt].nfs_resop4_u.opread.READ4res_u.resok4;
	rok->data.data_val = buffer;
	rok->data.data_len = buffer_size;
	/*COMPOUNDV4_ARG_ADD_OP_READ_STATE(opcnt, argoparray, offset +
	 * buffer_size, buffer_size, sid1);*/
	COMPOUNDV4_ARG_ADD_OP_READ(opcnt, argoparray, offset + buffer_size,
				   buffer_size);

	rc = fs_nfsv4_call(op_ctx->creds, NULL);
	if (rc != NFS4_OK)
		return nfsstat4_to_fsal(rc);

	*end_of_file = rok->eof;
	*read_amount = rok->data.data_len;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static inline void tc_prepare_putfh(nfs_fh4 *fh)
{
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, *fh);
}

static inline void tc_prepare_lookups(slice_t *comps, int compcnt)
{
        int i;

        for (i = 0; i < compcnt; ++i) {
                if (comps[i].size == 0)
                        continue;
                if (comps[i].data[0] == '.' && comps[i].size == 1)
                        continue;
		if (strncmp(comps[i].data, "..", comps[i].size) == 0) {
			COMPOUNDV4_ARG_ADD_OP_LOOKUPP(opcnt, argoparray);
		} else {
			COMPOUNDV4_ARG_ADD_OP_LOOKUPNAME(opcnt, argoparray,
							 comps[i].data,
							 comps[i].size);
		}
	}
}

static slice_t tc_get_abspath_from_cwd(slice_t rel_path)
{
        struct tc_cwd_data *cwd;
        buf_t *abs_path;

        cwd = tc_get_cwd();
        abs_path = tc_alloca_buf(PATH_MAX);
        assert(abs_path);
        tc_path_join_s(toslice(cwd->path), rel_path, abs_path);
        tc_put_cwd(cwd);

        return asslice(abs_path);
}

static int tc_set_cfh_from_cfh(const char *path, slice_t *leaf)
{
        slice_t *comps;
        slice_t p;
        int compcnt;

        if (leaf) {
                tc_path_dir_base(path, &p, leaf);
        } else {
                p = toslice(path);
        }

        compcnt = tc_path_tokenize_s(p, &comps);

        if (!tc_has_enough_ops(compcnt)) return -1;

        tc_prepare_lookups(comps, compcnt);

        return compcnt;
}

static int tc_set_cfh_from_root(slice_t *comps, int compcnt)
{
        if (!tc_has_enough_ops(compcnt + 1)) return -1;

        COMPOUNDV4_ARG_ADD_OP_PUTROOTFH(opcnt, argoparray);
        comps[0].data++;  // skip the leading '/'
        comps[0].size--;
        tc_prepare_lookups(comps, compcnt);

        return compcnt + 1;
}

static int tc_set_cfh_from_cwd(slice_t *comps, int compcnt)
{
        nfs_fh4 cwdfh;
        struct tc_cwd_data *cwd;

        if (!tc_has_enough_ops(compcnt + 1)) return -1;

        cwd = tc_get_cwd();
        cwdfh.nfs_fh4_val = tc_alloca(NFS4_FHSIZE);
        cwdfh.nfs_fh4_len = cwd->fh.nfs_fh4_len;
	memmove(cwdfh.nfs_fh4_val, cwd->fh.nfs_fh4_val, cwd->fh.nfs_fh4_len);
        tc_put_cwd(cwd);

	tc_prepare_putfh(&cwdfh);
        tc_prepare_lookups(comps, compcnt);

        return compcnt + 1;
}

static bool tc_compress_path(slice_t path, slice_t **comps, int *comps_n,
			     slice_t *abs_path)
{
        bool res;
        int short_comps_n;
        slice_t *short_comps;
        buf_t *short_path;

        if (path.size > 0 && path.data[0] == '/') {
                *abs_path = path;
        } else {
                *abs_path = tc_get_abspath_from_cwd(path);
        }
        *comps_n = tc_path_tokenize_s(path, comps);

        if (tc_saved_path[0] == 0) {
                return false;
        }

        short_path = tc_alloca_buf(PATH_MAX);
        if (!short_path) return false;
	if (tc_path_rebase_s(toslice(tc_saved_path), *abs_path, short_path) < 0)
		return false;

	NFS4_DEBUG("path compressed from %.*s to %.*s based on %s",
		   abs_path->size, abs_path->data, short_path->size,
		   short_path->data, tc_saved_path);
	short_comps_n = tc_path_tokenize_s(asslice(short_path), &short_comps);
        if (short_comps_n + 1 < *comps_n) {  // compressible
                *comps_n = short_comps_n;
                free(*comps);
                *comps = short_comps;
                res = true;
        } else {
                free(short_comps);
                res = false;
        }

        return res;
}

static inline void tc_prepare_savefh(slice_t *p)
{
        COMPOUNDV4_ARG_ADD_OP_SAVEFH(opcnt, argoparray);
        if (p) {
                tc_save_path(*p);
        } else {
                tc_saved_path[0] = '\0';  // clear saved path
        }
}

static inline void tc_prepare_restorefh()
{
	COMPOUNDV4_ARG_ADD_OP_RESTOREFH(opcnt, argoparray);
}

static int tc_set_cfh_to_path(const char *path, slice_t *leaf, bool save)
{
        slice_t abs_path;
        slice_t *comps;
        int comps_n;
        bool compressed;
        slice_t p;
        int r;

        if (leaf) {
                tc_path_dir_base(path, &p, leaf);
        } else {
                p = toslice(path);
        }

        compressed = tc_compress_path(p, &comps, &comps_n, &abs_path);
        if (compressed) {
                tc_prepare_restorefh();
                tc_prepare_lookups(comps, comps_n);
                r = comps_n + 1;
        } else if (path[0] == '/') {
                r = tc_set_cfh_from_root(comps, comps_n);
        } else {
                r = tc_set_cfh_from_cwd(comps, comps_n);
        }

        if (save) {
                tc_prepare_savefh(&p);
                r += 1;
        }

        free(comps);

        return r;
}

static int tc_set_cfh_to_handle(const struct file_handle *h)
{
	nfs_fh4 fh4;

	fh4.nfs_fh4_len = h->handle_bytes;
	fh4.nfs_fh4_val = (char *)h->f_handle;
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, fh4);

	return 1;
}

/**
 * Construct NFS lookups that will set current FH properly on the server side.
 * This is necessary before executing almost all operations.
 *
 * @param[in] tcf       The target file to set as current FH.
 * @param[in,out] leaf  Whether we should set current FH to the leaf node of the
 * of a long path, or stop at the parent of the leaf.  For example, when
 * creating a file at "/a/b/c/d", we need to set current FH to the directory
 * handle of the target file (i.e., "/a/b/c") and "leaf" should be NULL;
 * however, when getting attributes of file "/a/b/c/d", we need to set current
 * FH to "/a/b/c/d" and "leaf" should be not NULL.
 *
 * TODO: add support of other tc_file types; currently only TC_FILE_PATH is
 * supported.
 *
 * Returns the number of lookups appended to "argoparray".  If "leaf" is not
 * NULL, it will be set to the leaf component of the path.
 */
static int tc_set_current_fh(const tc_file *tcf, slice_t *leaf, bool save)
{
        int rc;

        if (tcf->type == TC_FILE_CURRENT) {
                rc = tc_set_cfh_from_cfh(tcf->path, leaf);
        } else if (tcf->type == TC_FILE_HANDLE) {
                rc = tc_set_cfh_to_handle(tcf->handle);
                fillslice(leaf, NULL, 0);
	} else if (tcf->type == TC_FILE_DESCRIPTOR) {
		tc_prepare_putfh(((struct nfs4_fd_data *)tcf->fd_data)->fh4);
                rc = 1;
                fillslice(leaf, NULL, 0);
	} else if (tcf->type == TC_FILE_PATH) {
		rc = tc_set_cfh_to_path(tcf->path, leaf, save);
	} else {
		NFS4_ERR("unsupported type: %d", tcf->type);
		rc = -1;
	}

	return rc;
}

static int tc_set_saved_fh(const tc_file *tcf, slice_t *leaf)
{
        int rc;

        if (tcf->type == TC_FILE_PATH) {
                rc = tc_set_cfh_to_path(tcf->path, leaf, true);
        } else {
                rc = tc_set_current_fh(tcf, leaf, false);
                tc_prepare_savefh(NULL);
                rc += 1;
        }

        return rc;
}

static nfsstat4 get_nfs4_op_status(const nfs_resop4 *op_res)
{
	switch (op_res->resop) {
	case NFS4_OP_ACCESS: /* 3 */
		return op_res->nfs_resop4_u.opaccess.status;
	case NFS4_OP_CLOSE: /* 4 */
		return op_res->nfs_resop4_u.opclose.status;
	case NFS4_OP_COMMIT: /* 5 */
		return op_res->nfs_resop4_u.opcommit.status;
	case NFS4_OP_CREATE: /* 6 */
		return op_res->nfs_resop4_u.opcreate.status;
	case NFS4_OP_DELEGPURGE: /* 7 */
		return op_res->nfs_resop4_u.opdelegpurge.status;
	case NFS4_OP_DELEGRETURN: /* 8 */
		return op_res->nfs_resop4_u.opdelegreturn.status;
	case NFS4_OP_GETATTR: /* 9 */
		return op_res->nfs_resop4_u.opgetattr.status;
	case NFS4_OP_GETFH: /* 10 */
		return op_res->nfs_resop4_u.opgetfh.status;
	case NFS4_OP_LINK: /* 11 */
		return op_res->nfs_resop4_u.oplink.status;
	case NFS4_OP_LOCK: /* 12 */
		return op_res->nfs_resop4_u.oplock.status;
	case NFS4_OP_LOCKT: /* 13 */
		return op_res->nfs_resop4_u.oplockt.status;
	case NFS4_OP_LOCKU: /* 14 */
		return op_res->nfs_resop4_u.oplocku.status;
	case NFS4_OP_LOOKUP: /* 15 */
		return op_res->nfs_resop4_u.oplookup.status;
	case NFS4_OP_LOOKUPP: /* 16 */
		return op_res->nfs_resop4_u.oplookupp.status;
	case NFS4_OP_NVERIFY: /* 17 */
		return op_res->nfs_resop4_u.opnverify.status;
	case NFS4_OP_OPEN: /* 18 */
		return op_res->nfs_resop4_u.opopen.status;
	case NFS4_OP_OPENATTR: /* 19 */
		return op_res->nfs_resop4_u.opopenattr.status;
	case NFS4_OP_OPEN_CONFIRM: /* 20 */
		return op_res->nfs_resop4_u.opopen_confirm.status;
	case NFS4_OP_OPEN_DOWNGRADE: /* 21 */
		return op_res->nfs_resop4_u.opopen_downgrade.status;
	case NFS4_OP_PUTFH: /* 22 */
		return op_res->nfs_resop4_u.opputfh.status;
	case NFS4_OP_PUTPUBFH: /* 23 */
		return op_res->nfs_resop4_u.opputpubfh.status;
	case NFS4_OP_PUTROOTFH: /* 24 */
		return op_res->nfs_resop4_u.opputrootfh.status;
	case NFS4_OP_READ: /* 25 */
		return op_res->nfs_resop4_u.opread.status;
	case NFS4_OP_READDIR: /* 26 */
		return op_res->nfs_resop4_u.opreaddir.status;
	case NFS4_OP_READLINK: /* 27 */
		return op_res->nfs_resop4_u.opreadlink.status;
	case NFS4_OP_REMOVE: /* 28 */
		return op_res->nfs_resop4_u.opremove.status;
	case NFS4_OP_RENAME: /* 29 */
		return op_res->nfs_resop4_u.oprename.status;
	case NFS4_OP_RENEW: /* 30 */
		return op_res->nfs_resop4_u.oprenew.status;
	case NFS4_OP_RESTOREFH: /* 31 */
		return op_res->nfs_resop4_u.oprestorefh.status;
	case NFS4_OP_SAVEFH: /* 32 */
		return op_res->nfs_resop4_u.opsavefh.status;
	case NFS4_OP_SECINFO: /* 33 */
		return op_res->nfs_resop4_u.opsecinfo.status;
	case NFS4_OP_SETATTR: /* 34 */
		return op_res->nfs_resop4_u.opsetattr.status;
	case NFS4_OP_SETCLIENTID: /* 35 */
		return op_res->nfs_resop4_u.opsetclientid.status;
	case NFS4_OP_SETCLIENTID_CONFIRM: /* 36 */
		return op_res->nfs_resop4_u.opsetclientid_confirm.status;
	case NFS4_OP_VERIFY: /* 37 */
		return op_res->nfs_resop4_u.opverify.status;
	case NFS4_OP_WRITE: /* 38 */
		return op_res->nfs_resop4_u.opwrite.status;
        case NFS4_OP_EXCHANGE_ID: /* 43 */
                return op_res->nfs_resop4_u.opexchange_id.eir_status;
        case NFS4_OP_CREATE_SESSION: /* 43 */
                return op_res->nfs_resop4_u.opcreate_session.csr_status;
        case NFS4_OP_DESTROY_SESSION: /* 44 */
                return op_res->nfs_resop4_u.opdestroy_session.dsr_status;
        case NFS4_OP_FREE_STATEID: /* 45 */
                return op_res->nfs_resop4_u.opfree_stateid.fsr_status;
        case NFS4_OP_SEQUENCE: /* 53 */
                return op_res->nfs_resop4_u.opsequence.sr_status;
        case NFS4_OP_DESTROY_CLIENTID: /* 57 */
                return op_res->nfs_resop4_u.opdestroy_clientid.dcr_status;
	case NFS4_OP_COPY: /* 60 */
		return op_res->nfs_resop4_u.opcopy.cr_status;
	default:
		NFS4_ERR("not supported operation: %d", op_res->resop);
	}
	return NFS4ERR_IO;
}

static inline void tc_prepare_rdwr(struct tc_iovec *iov, bool write);

static bool tc_open_file_if_necessary(const tc_file *tcf, int flags,
				      buf_t *pbuf_owner, fattr4 *attrs4,
				      const tc_file **opened_file);

/**
 * Send multiple reads for one or more files
 * "iovs" - an array of tc_iovec with size "count"
 * tc_res.index - Returns the position (read) inside the array that failed (in
 * case of failure)  The failure could be in putrootfh, lookup, open, read or
 * close, tc_res.index  would only point to the read call because it is unaware
 * of the putrootfh, lookup, open or close.
 * Caller has to make sure iovs and fields inside are allocated and freed.
 */
static tc_res tc_nfs4_readv(struct tc_iovec *iovs, int count)
{
	tc_res tcres = { 0 };
	int rc;
	nfsstat4 op_status;
	struct READ4resok *read_res;
	int i = 0;      /* index of tc_iovec */
	int j = 0;      /* index of NFS operations */
        const tc_file *opened_file = NULL;

	LogDebug(COMPONENT_FSAL, "ktcread() called\n");

        tc_reset_compound(true);

	for (i = 0; i < count; ++i) {
		tc_open_file_if_necessary(&iovs[i].file, O_RDONLY,
					  new_auto_buf(64), NULL, &opened_file);
		tc_prepare_rdwr(&iovs[i], false);
	}

	if (opened_file) {
		COMPOUNDV4_ARG_ADD_OP_CLOSE_NOSTATE(opcnt, argoparray);
                opened_file = NULL;
	}

	rc = fs_nfsv4_call(op_ctx->creds, &tcres.err_no);
	if (rc != RPC_SUCCESS) {    /* RPC failed */
                NFS4_ERR("fs_nfsv4_call() returned error: %d\n", rc);
                tcres = tc_failure(0, rc);
                goto exit;
        }

        /* No matter NFS failed or succeeded, we need to fill in results */
        i = 0;
        for (j = 0; j < opcnt; ++j) {
                op_status = get_nfs4_op_status(&resoparray[j]);
                if (op_status != NFS4_OK) {
			iovs[i].is_failure = 1;
			NFS4_ERR("the %d-th tc_iovec failed (NFS op: %d)", i,
				 resoparray[j].resop);
                        tcres = tc_failure(i, nfsstat4_to_errno(op_status));
                        goto exit;
                }
                if (resoparray[j].resop == NFS4_OP_READ) {
			read_res = &resoparray[j]
					.nfs_resop4_u.opread.READ4res_u.resok4;
			iovs[i].length = read_res->data.data_len;
			iovs[i].is_eof = read_res->eof;
                        i++;
		}
	}

exit:
        return tcres;
}

static inline void tc_prepare_rdwr(struct tc_iovec *iov, bool write)
{
	size_t offset = iov->offset;
	struct nfs4_fd_data *fd_data;
	const stateid4 *sid = &CURSID;
	READ4resok *rok;

	if (iov->file.type == TC_FILE_DESCRIPTOR) {
		fd_data = (struct nfs4_fd_data *)iov->file.fd_data;
		if (offset == TC_OFFSET_CUR) {
			offset = fd_data->fd_cursor;
		}
		sid = fd_data->stateid;
	}
	if (write) {
		COMPOUNDV4_ARG_ADD_OP_WRITE_STATE(opcnt, argoparray, offset,
						  iov->data, iov->length, sid);
	} else {
		rok = &resoparray[opcnt].nfs_resop4_u.opread.READ4res_u.resok4;
		rok->data.data_val = iov->data;
		rok->data.data_len = iov->length;
		COMPOUNDV4_ARG_ADD_OP_READ_STATE(opcnt, argoparray, offset,
						 iov->length, sid);
	}
}

/*
 * Send multiple reads for one or more files
 * "iovs" - an array of tc_iovec with size "count"
 * tc_res.index - Returns the position (write) inside the array that failed (in
 * case of failure)  The failure could be in putrootfh, lookup, open, read or
 * close, tc_res.index  would only point to the read call because it is unaware
 * of the putrootfh, lookup, open or close.
 * Caller has to make sure iovs and fields inside are allocated and freed.
 */
static tc_res tc_nfs4_writev(struct tc_iovec *iovs, int count)
{
	tc_res tcres = { 0 };
	int rc;
	nfsstat4 op_status;
        struct WRITE4resok *write_res = NULL;
	fattr4 *input_attr = NULL;
	int i = 0;      /* index of tc_iovec */
	int j = 0;      /* index of NFS operations */
        const tc_file *opened_file = NULL;

	LogDebug(COMPONENT_FSAL, "ktcwrite() called\n");

        tc_reset_compound(true);

	input_attr = calloc(count, sizeof(fattr4));

	for (i = 0; i < count; ++i) {
		tc_open_file_if_necessary(
		    &iovs[i].file,
		    O_WRONLY | (iovs[i].is_creation ? O_CREAT : 0),
		    new_auto_buf(64), &input_attr[i], &opened_file);
		tc_prepare_rdwr(&iovs[i], true);
	}

	if (opened_file) {
		COMPOUNDV4_ARG_ADD_OP_CLOSE(opcnt, argoparray, (&CURSID));
                opened_file = NULL;
	}

	rc = fs_nfsv4_call(op_ctx->creds, &tcres.err_no);
	if (rc != RPC_SUCCESS) {
		NFS4_ERR("fs_nfsv4_call() returned error: %d (%s)\n", rc,
			 strerror(rc));
                tcres = tc_failure(0, rc);
                goto exit;
	}

        /* No matter failure or success, we need to fill in results */
        i = 0;
        for (j = 0; j < opcnt; ++j) {
                op_status = get_nfs4_op_status(&resoparray[j]);
                if (op_status != NFS4_OK) {
                        iovs[i].is_failure = 1;
                        tcres = tc_failure(i, nfsstat4_to_errno(op_status));
			NFS4_ERR("the %d-th tc_iovec failed (NFS op: %d)", i,
				 resoparray[j].resop);
                        goto exit;
                }
                if (resoparray[j].resop == NFS4_OP_WRITE) {
			write_res =
			    &resoparray[j]
				 .nfs_resop4_u.opwrite.WRITE4res_u.resok4;
			iovs[i].length = write_res->count;
			iovs[i].is_write_stable =
			    (write_res->committed != UNSTABLE4);
			i++;
                }
        }

exit:
	for (i = 0; i < count; ++i) {
		nfs4_Fattr_Free(&input_attr[i]);
	}
	free(input_attr);
        return tcres;
}

static inline uint32_t tc_open_flags_to_access(int flags)
{
	if ((flags & O_WRONLY) != 0) {
		return OPEN4_SHARE_ACCESS_WRITE;
	} else if ((flags & O_RDWR) != 0) {
		return OPEN4_SHARE_ACCESS_BOTH;
	} else {
		return OPEN4_SHARE_ACCESS_READ;
	}
}

static inline CREATE4resok *tc_prepare_mkdir(const char *name, fattr4 *fattr)
{
	CREATE4resok *crok;

	NFS4_DEBUG("op (%d) of compound: mkdir(\"%s\")", opcnt, name);
	crok = &resoparray[opcnt].nfs_resop4_u.opcreate.CREATE4res_u.resok4;
	crok->attrset = empty_bitmap;
	COMPOUNDV4_ARG_ADD_OP_MKDIR(opcnt, argoparray, (char *)name, *fattr);

	return crok;
}

/**
 * Set up the GETATTR operation.
 */
static inline GETATTR4resok *tc_prepare_getattr(char *fattr_blob,
						const struct bitmap4 *bm4)
{
	GETATTR4resok *atok;

	atok = fs_fill_getattr_reply(resoparray + opcnt, fattr_blob,
				     FATTR_BLOB_SZ);
	COMPOUNDV4_ARG_ADD_OP_GETATTR(opcnt, argoparray, *bm4);

        return atok;
}

/**
 * Set up the SETATTR operation.
 */
static inline SETATTR4res *tc_prepare_setattr(const fattr4 *fattr)
{
        SETATTR4res *res;

	res = &resoparray[opcnt].nfs_resop4_u.opsetattr;
	resoparray[opcnt].nfs_resop4_u.opsetattr.attrsset = empty_bitmap;
	COMPOUNDV4_ARG_ADD_OP_SETATTR(opcnt, argoparray, *fattr);

        return res;
}

/**
 * Set up the GETFH operation.
 */
static inline GETFH4resok *tc_prepare_getfh(char *fh)
{
	GETFH4resok *fhok;

	fhok = &resoparray[opcnt].nfs_resop4_u.opgetfh.GETFH4res_u.resok4;
	fhok->object.nfs_fh4_val = fh;
	fhok->object.nfs_fh4_len = NFS4_FHSIZE;
	COMPOUNDV4_ARG_ADD_OP_GETFH(opcnt, argoparray);

        return fhok;
}

/**
 * TODO: deal with opening file by handle
 * @owner_pbuf: pbuf for owner
 * @attrs: initial attributes for file creation.
 */
static inline OPEN4resok *tc_prepare_open(slice_t name, int flags,
                                          buf_t *owner_pbuf, fattr4 *attrs)
{
	OPEN4resok *opok;
	clientid4 cid;
	OPEN4args *args;

	tc_new_state_owner(owner_pbuf);
	tc_get_clientid(&cid);

	argoparray[opcnt].argop = NFS4_OP_OPEN;
	args = &argoparray[opcnt].nfs_argop4_u.opopen;
	args->seqid = 0;
	args->share_access = tc_open_flags_to_access(flags);
	args->share_deny = OPEN4_SHARE_DENY_NONE;

	args->owner.clientid = cid;
	args->owner.owner.owner_val = owner_pbuf->data;
	args->owner.owner.owner_len = owner_pbuf->size;

	if (flags & O_CREAT) {
		args->openhow.opentype = OPEN4_CREATE;
		args->openhow.openflag4_u.how.mode =
		    (flags & O_EXCL) ? GUARDED4 : UNCHECKED4;
		args->openhow.openflag4_u.how.createhow4_u.createattrs = *attrs;
	} else {
                assert(!(flags & O_CREAT));
		args->openhow.opentype = OPEN4_NOCREATE;
	}

	args->claim.claim = CLAIM_NULL;
	args->claim.open_claim4_u.file.utf8string_val = (char *)name.data;
	args->claim.open_claim4_u.file.utf8string_len = name.size;

	opok = &resoparray[opcnt].nfs_resop4_u.opopen.OPEN4res_u.resok4;
	opcnt += 1;

	return opok;
}

/* The caller should release "rdok->reply.entries" */
static inline READDIR4resok *tc_prepare_readdir(nfs_cookie4 *cookie,
						const struct bitmap4 *attrbm)
{
	READDIR4resok *rdok;

	rdok = &resoparray[opcnt].nfs_resop4_u.opreaddir.READDIR4res_u.resok4;
	rdok->reply.entries = NULL;
	COMPOUNDV4_ARG_ADD_OP_READDIR(opcnt, argoparray, *cookie,
				      (attrbm ? *attrbm : tc_bitmap_readdir));

	return rdok;
}

static inline REMOVE4resok *tc_prepare_remove(char *name)
{
        REMOVE4resok *rmok;

	rmok = &resoparray[opcnt].nfs_resop4_u.opremove.REMOVE4res_u.resok4;
	COMPOUNDV4_ARG_ADD_OP_REMOVE(opcnt, argoparray, name);

        return rmok;
}

static inline COPY4res *tc_prepare_copy(size_t src_offset, size_t dst_offset,
					size_t count)
{
	COPY4res *cpres;

	cpres = &resoparray[opcnt].nfs_resop4_u.opcopy;
	COMPOUNDV4_ARG_ADD_OP_COPY(opcnt, argoparray, src_offset, dst_offset,
				   count);

	return cpres;
}

static inline utf8string slice2ustr(const slice_t *sl) {
        utf8string ustr = {
                .utf8string_val = (char *)sl->data,
                .utf8string_len = sl->size,
        };
        return ustr;
}

static inline RENAME4resok *tc_prepare_rename(const slice_t *srcname,
                                              const slice_t *dstname)
{
	RENAME4resok *rnok;
	nfs_argop4 *op;

	op = argoparray + opcnt;
	rnok = &resoparray[opcnt].nfs_resop4_u.oprename.RENAME4res_u.resok4;
	op->argop = NFS4_OP_RENAME;
	op->nfs_argop4_u.oprename.oldname = slice2ustr(srcname);
	op->nfs_argop4_u.oprename.newname = slice2ustr(dstname);
	opcnt++;

	return rnok;
}

static inline void tc_file_set_handle(tc_file *tcf, const nfs_fh4 *fh4)
{
        tcf->type = TC_FILE_HANDLE;
        tcf->handle = new_file_handle(fh4->nfs_fh4_len, fh4->nfs_fh4_val);
}

static fsal_status_t fs_mkdir(struct fsal_obj_handle *dir_hdl, const char *name,
			      struct attrlist *attrib,
			      struct fsal_obj_handle **handle)
{
	int rc;
	fattr4 input_attr;
	char padfilehandle[NFS4_FHSIZE];
	struct fs_obj_handle *ph;
	char fattr_blob[FATTR_BLOB_SZ];
	GETATTR4resok *atok;
	GETFH4resok *fhok;
	fsal_status_t st;

	/*
	 * The caller gives us partial attributes which include mode and owner
	 * and expects the full attributes back at the end of the call.
	 */
	attrib->mask &= ATTR_MODE | ATTR_OWNER | ATTR_GROUP;
	if (fs_fsalattr_to_fattr4(attrib, &input_attr) == -1)
		return fsalstat(ERR_FSAL_INVAL, -1);

        tc_reset_compound(true);

	ph = container_of(dir_hdl, struct fs_obj_handle, obj);
        tc_prepare_putfh(&ph->fh4);

        tc_prepare_mkdir(name, &input_attr);

	fhok = tc_prepare_getfh(padfilehandle);

	atok = tc_prepare_getattr(fattr_blob, &fs_bitmap_getattr);

	rc = fs_nfsv4_call(op_ctx->creds, NULL);
	nfs4_Fattr_Free(&input_attr);
	if (rc != NFS4_OK) {
		st = nfsstat4_to_fsal(rc);
                goto exit;
        }

	st = fs_make_object(op_ctx->fsal_export, &atok->obj_attributes,
			    &fhok->object, handle);
	if (!FSAL_IS_ERROR(st))
		*attrib = (*handle)->attributes;

exit:
	return st;
}

static fsal_status_t fs_mknod(struct fsal_obj_handle *dir_hdl,
			       const char *name, object_file_type_t nodetype,
			       fsal_dev_t *dev, struct attrlist *attrib,
			       struct fsal_obj_handle **handle)
{
	int rc;
	fattr4 input_attr;
	char padfilehandle[NFS4_FHSIZE];
	struct fs_obj_handle *ph;
	char fattr_blob[FATTR_BLOB_SZ];
	GETATTR4resok *atok;
	GETFH4resok *fhok;
	fsal_status_t st;
	enum nfs_ftype4 nf4type;
	specdata4 specdata = { 0, 0 };

	switch (nodetype) {
	case CHARACTER_FILE:
		if (!dev)
			return fsalstat(ERR_FSAL_FAULT, EINVAL);
		specdata.specdata1 = dev->major;
		specdata.specdata2 = dev->minor;
		nf4type = NF4CHR;
		break;
	case BLOCK_FILE:
		if (!dev)
			return fsalstat(ERR_FSAL_FAULT, EINVAL);
		specdata.specdata1 = dev->major;
		specdata.specdata2 = dev->minor;
		nf4type = NF4BLK;
		break;
	case SOCKET_FILE:
		nf4type = NF4SOCK;
		break;
	case FIFO_FILE:
		nf4type = NF4FIFO;
		break;
	default:
		return fsalstat(ERR_FSAL_FAULT, EINVAL);
	}

	/*
	 * The caller gives us partial attributes which include mode and owner
	 * and expects the full attributes back at the end of the call.
	 */
	attrib->mask &= ATTR_MODE | ATTR_OWNER | ATTR_GROUP;
	if (fs_fsalattr_to_fattr4(attrib, &input_attr) == -1)
		return fsalstat(ERR_FSAL_INVAL, -1);

        tc_reset_compound(true);

	ph = container_of(dir_hdl, struct fs_obj_handle, obj);
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);

	resoparray[opcnt].nfs_resop4_u.opcreate.CREATE4res_u.resok4.attrset =
	    empty_bitmap;
	COMPOUNDV4_ARG_ADD_OP_CREATE(opcnt, argoparray, (char *)name, nf4type,
				     input_attr, specdata);

	fhok = &resoparray[opcnt].nfs_resop4_u.opgetfh.GETFH4res_u.resok4;
	fhok->object.nfs_fh4_val = padfilehandle;
	fhok->object.nfs_fh4_len = sizeof(padfilehandle);
	COMPOUNDV4_ARG_ADD_OP_GETFH(opcnt, argoparray);

	atok =
	    fs_fill_getattr_reply(resoparray + opcnt, fattr_blob,
				   sizeof(fattr_blob));
	COMPOUNDV4_ARG_ADD_OP_GETATTR(opcnt, argoparray, fs_bitmap_getattr);

	rc = fs_nfsv4_call(op_ctx->creds, NULL);
	nfs4_Fattr_Free(&input_attr);
	if (rc != NFS4_OK)
		return nfsstat4_to_fsal(rc);

	st = fs_make_object(op_ctx->fsal_export,
			     &atok->obj_attributes,
			     &fhok->object, handle);
	if (!FSAL_IS_ERROR(st))
		*attrib = (*handle)->attributes;
	return st;
}

static void tc_prepare_symlink(char *name, char *link_path, fattr4 *attrs)
{
	resoparray[opcnt].nfs_resop4_u.opcreate.CREATE4res_u.resok4.attrset =
	    empty_bitmap;
	COMPOUNDV4_ARG_ADD_OP_SYMLINK(opcnt, argoparray, (char *)name,
				      (char *)link_path, (*attrs));
}

static fsal_status_t fs_symlink(struct fsal_obj_handle *dir_hdl,
				 const char *name, const char *link_path,
				 struct attrlist *attrib,
				 struct fsal_obj_handle **handle)
{
	int rc;
	fattr4 input_attr;
	char padfilehandle[NFS4_FHSIZE];
	char fattr_blob[FATTR_BLOB_SZ];
	GETATTR4resok *atok;
	GETFH4resok *fhok;
	fsal_status_t st;
	struct fs_obj_handle *ph;

	/* Tests if symlinking is allowed by configuration. */
	if (!op_ctx->fsal_export->ops->fs_supports(op_ctx->fsal_export,
						  fso_symlink_support))
		return fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);

	attrib->mask = ATTR_MODE;
	if (fs_fsalattr_to_fattr4(attrib, &input_attr) == -1)
		return fsalstat(ERR_FSAL_INVAL, -1);

        tc_reset_compound(true);
	ph = container_of(dir_hdl, struct fs_obj_handle, obj);
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);

        tc_prepare_symlink((char *)name, (char *)link_path, &input_attr);

	fhok = &resoparray[opcnt].nfs_resop4_u.opgetfh.GETFH4res_u.resok4;
	fhok->object.nfs_fh4_val = padfilehandle;
	fhok->object.nfs_fh4_len = sizeof(padfilehandle);
	COMPOUNDV4_ARG_ADD_OP_GETFH(opcnt, argoparray);

	atok =
	    fs_fill_getattr_reply(resoparray + opcnt, fattr_blob,
				   sizeof(fattr_blob));
	COMPOUNDV4_ARG_ADD_OP_GETATTR(opcnt, argoparray, fs_bitmap_getattr);

	rc = fs_nfsv4_call(op_ctx->creds, NULL);
	nfs4_Fattr_Free(&input_attr);
	if (rc != NFS4_OK)
		return nfsstat4_to_fsal(rc);

	st = fs_make_object(op_ctx->fsal_export,
			     &atok->obj_attributes,
			     &fhok->object, handle);
	if (!FSAL_IS_ERROR(st))
		*attrib = (*handle)->attributes;
	return st;
}

static READLINK4resok *tc_prepare_readlink(char *buf, size_t buf_size)
{
	READLINK4resok *rlok;

	rlok = &resoparray[opcnt].nfs_resop4_u.opreadlink.READLINK4res_u.resok4;
	rlok->link.utf8string_val = buf;
	rlok->link.utf8string_len = buf_size;
	argoparray[opcnt].argop = NFS4_OP_READLINK;
	opcnt++;

	return rlok;
}

static fsal_status_t fs_readlink(struct fsal_obj_handle *obj_hdl,
				  struct gsh_buffdesc *link_content,
				  bool refresh)
{
	int rc;
	struct fs_obj_handle *ph;
	READLINK4resok *rlok;

        tc_reset_compound(true);
	ph = container_of(obj_hdl, struct fs_obj_handle, obj);
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);

	/* This saves us from having to do one allocation for the XDR,
	   another allocation for the return, and a copy just to get
	   the \NUL terminator. The link length should be cached in
	   the file handle. */

	link_content->len =
	    obj_hdl->attributes.filesize ? (obj_hdl->attributes.filesize +
					    1) : fsal_default_linksize;
	link_content->addr = gsh_calloc(1, link_content->len);

	if (link_content->addr == NULL)
		return fsalstat(ERR_FSAL_NOMEM, 0);

        rlok = tc_prepare_readlink(link_content->addr, link_content->len);

	rc = fs_nfsv4_call(op_ctx->creds, NULL);
	if (rc != NFS4_OK) {
		gsh_free(link_content->addr);
		link_content->addr = NULL;
		link_content->len = 0;
		return nfsstat4_to_fsal(rc);
	}

	rlok->link.utf8string_val[rlok->link.utf8string_len] = '\0';
	link_content->len = rlok->link.utf8string_len + 1;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static fsal_status_t fs_link(struct fsal_obj_handle *obj_hdl,
			      struct fsal_obj_handle *destdir_hdl,
			      const char *name)
{
	int rc;
	struct fs_obj_handle *tgt;
	struct fs_obj_handle *dst;

	/* Tests if hardlinking is allowed by configuration. */
	if (!op_ctx->fsal_export->ops->fs_supports(op_ctx->fsal_export,
						  fso_link_support))
		return fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);

	tgt = container_of(obj_hdl, struct fs_obj_handle, obj);
	dst = container_of(destdir_hdl, struct fs_obj_handle, obj);

        tc_reset_compound(true);

	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, tgt->fh4);
        tc_prepare_savefh(NULL);
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, dst->fh4);
	COMPOUNDV4_ARG_ADD_OP_LINK(opcnt, argoparray, (char *)name);

	rc = fs_nfsv4_call(op_ctx->creds, NULL);
	return nfsstat4_to_fsal(rc);
}

static bool xdr_readdirres(XDR *x, nfs_resop4 *rdres)
{
	return xdr_nfs_resop4(x, rdres) && xdr_nfs_resop4(x, rdres + 1);
}

/*
 * Trying to guess how many entries can fit into a readdir buffer
 * is complicated and usually results in either gross over-allocation
 * of the memory for results or under-allocation (on large directories)
 * and buffer overruns - just pay the price of allocating the memory
 * inside XDR decoding and free it when done
 */
static fsal_status_t fs_do_readdir(struct fs_obj_handle *ph,
				    nfs_cookie4 *cookie, fsal_readdir_cb cb,
				    void *cbarg, bool *eof)
{
	int rc;
	entry4 *e4;
	READDIR4resok *rdok;
	fsal_status_t st = { ERR_FSAL_NO_ERROR, 0 };

        tc_reset_compound(true);
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);
	rdok = &resoparray[opcnt].nfs_resop4_u.opreaddir.READDIR4res_u.resok4;
	rdok->reply.entries = NULL;
	COMPOUNDV4_ARG_ADD_OP_READDIR(opcnt, argoparray, *cookie,
				      fs_bitmap_readdir);

	rc = fs_nfsv4_call(op_ctx->creds, NULL);
	if (rc != NFS4_OK)
		return nfsstat4_to_fsal(rc);

	*eof = rdok->reply.eof;

	for (e4 = rdok->reply.entries; e4; e4 = e4->nextentry) {
		struct attrlist attr = {0};
		char name[MAXNAMLEN + 1];

		/* UTF8 name does not include trailing 0 */
		if (e4->name.utf8string_len > sizeof(name) - 1)
			return fsalstat(ERR_FSAL_SERVERFAULT, E2BIG);
		memcpy(name, e4->name.utf8string_val, e4->name.utf8string_len);
		name[e4->name.utf8string_len] = '\0';

		if (nfs4_Fattr_To_FSAL_attr(&attr, &e4->attrs, NULL))
			return fsalstat(ERR_FSAL_FAULT, 0);

		*cookie = e4->cookie;

		if (!cb(name, cbarg, e4->cookie))
			break;
	}
	xdr_free((xdrproc_t) xdr_readdirres, resoparray);
	return st;
}

/* What to do about verifier if server needs one? */
static fsal_status_t fs_readdir(struct fsal_obj_handle *dir_hdl,
				 fsal_cookie_t *whence, void *cbarg,
				 fsal_readdir_cb cb, bool *eof)
{
	nfs_cookie4 cookie = 0;
	struct fs_obj_handle *ph;

	if (whence)
		cookie = (nfs_cookie4) *whence;

	ph = container_of(dir_hdl, struct fs_obj_handle, obj);

	do {
		fsal_status_t st;

		st = fs_do_readdir(ph, &cookie, cb, cbarg, eof);
		if (FSAL_IS_ERROR(st))
			return st;
	} while (*eof == false);

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static fsal_status_t fs_rename(struct fsal_obj_handle *olddir_hdl,
				const char *old_name,
				struct fsal_obj_handle *newdir_hdl,
				const char *new_name)
{
	int rc;
	struct fs_obj_handle *src;
	struct fs_obj_handle *tgt;

        tc_reset_compound(true);
	src = container_of(olddir_hdl, struct fs_obj_handle, obj);
	tgt = container_of(newdir_hdl, struct fs_obj_handle, obj);
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, src->fh4);
        tc_prepare_savefh(NULL);
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, tgt->fh4);
	COMPOUNDV4_ARG_ADD_OP_RENAME(opcnt, argoparray, (char *)old_name,
				     (char *)new_name);

	rc = fs_nfsv4_call(op_ctx->creds, NULL);
	return nfsstat4_to_fsal(rc);
}

static fsal_status_t fs_getattrs_impl(const struct user_cred *creds,
				       struct fsal_export *exp,
				       nfs_fh4 *filehandle,
				       struct attrlist *obj_attr)
{
	int rc;
	GETATTR4resok *atok;
	char fattr_blob[FATTR_BLOB_SZ];

        tc_reset_compound(true);
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, *filehandle);

	atok = fs_fill_getattr_reply(resoparray + opcnt, fattr_blob,
				      sizeof(fattr_blob));
	COMPOUNDV4_ARG_ADD_OP_GETATTR(opcnt, argoparray, fs_bitmap_getattr);

	rc = fs_nfsv4_call(creds, NULL);
	if (rc != NFS4_OK)
		return nfsstat4_to_fsal(rc);

	if (nfs4_Fattr_To_FSAL_attr(obj_attr, &atok->obj_attributes, NULL) !=
	    NFS4_OK)
		return fsalstat(ERR_FSAL_INVAL, 0);

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static fsal_status_t fs_getattrs(struct fsal_obj_handle *obj_hdl)
{
	struct fs_obj_handle *ph;
	fsal_status_t st;
	struct attrlist obj_attr = {0};

	ph = container_of(obj_hdl, struct fs_obj_handle, obj);
	st = fs_getattrs_impl(op_ctx->creds, op_ctx->fsal_export,
			       &ph->fh4, &obj_attr);
	if (!FSAL_IS_ERROR(st))
		obj_hdl->attributes = obj_attr;
	return st;
}

/*
 * Couple of things to note:
 * 1. We assume that checks for things like cansettime are done
 *    by the caller.
 * 2. attrs can be modified in this function but caller cannot
 *    assume that the attributes are up-to-date
 */
static fsal_status_t fs_setattrs(struct fsal_obj_handle *obj_hdl,
				  struct attrlist *attrs)
{
	int rc;
	fattr4 input_attr;
	struct fs_obj_handle *ph;
	char fattr_blob[FATTR_BLOB_SZ];
	GETATTR4resok *atok;
	struct attrlist attrs_after = {0};

	if (FSAL_TEST_MASK(attrs->mask, ATTR_MODE))
		attrs->mode &= ~op_ctx->fsal_export->ops->
				fs_umask(op_ctx->fsal_export);

	ph = container_of(obj_hdl, struct fs_obj_handle, obj);

	if (fs_fsalattr_to_fattr4(attrs, &input_attr) == -1)
		return fsalstat(ERR_FSAL_INVAL, EINVAL);

        tc_reset_compound(true);
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);

	resoparray[opcnt].nfs_resop4_u.opsetattr.attrsset = empty_bitmap;
	COMPOUNDV4_ARG_ADD_OP_SETATTR(opcnt, argoparray, input_attr);

	atok =
	    fs_fill_getattr_reply(resoparray + opcnt, fattr_blob,
				   sizeof(fattr_blob));
	COMPOUNDV4_ARG_ADD_OP_GETATTR(opcnt, argoparray, fs_bitmap_getattr);

	rc = fs_nfsv4_call(op_ctx->creds, NULL);
	nfs4_Fattr_Free(&input_attr);
	if (rc != NFS4_OK)
		return nfsstat4_to_fsal(rc);

	rc = nfs4_Fattr_To_FSAL_attr(&attrs_after, &atok->obj_attributes, NULL);
	if (rc != NFS4_OK) {
		LogWarn(COMPONENT_FSAL,
			"Attribute conversion fails with %d, "
			"ignoring attibutes after making changes", rc);
	} else {
		obj_hdl->attributes = attrs_after;
	}

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static bool fs_handle_is(struct fsal_obj_handle *obj_hdl,
			  object_file_type_t type)
{
	return obj_hdl->type == type;
}

static fsal_status_t fs_unlink(struct fsal_obj_handle *dir_hdl,
				const char *name)
{
	int rc;
	struct fs_obj_handle *ph;
	GETATTR4resok *atok;
	char fattr_blob[FATTR_BLOB_SZ];
	struct attrlist dirattr = {0};

        tc_reset_compound(true);
	ph = container_of(dir_hdl, struct fs_obj_handle, obj);
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);
	COMPOUNDV4_ARG_ADD_OP_REMOVE(opcnt, argoparray, (char *)name);

	atok = fs_fill_getattr_reply(resoparray + opcnt, fattr_blob,
				     sizeof(fattr_blob));
	COMPOUNDV4_ARG_ADD_OP_GETATTR(opcnt, argoparray, fs_bitmap_getattr);

	rc = fs_nfsv4_call(op_ctx->creds, NULL);
	if (rc != NFS4_OK)
		return nfsstat4_to_fsal(rc);

	if (nfs4_Fattr_To_FSAL_attr(&dirattr, &atok->obj_attributes, NULL) ==
	    NFS4_OK)
		dir_hdl->attributes = dirattr;

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static fsal_status_t fs_handle_digest(const struct fsal_obj_handle *obj_hdl,
				       fsal_digesttype_t output_type,
				       struct gsh_buffdesc *fh_desc)
{
	struct fs_obj_handle *ph =
	    container_of(obj_hdl, struct fs_obj_handle, obj);
	size_t fhs;
	void *data;

	/* sanity checks */
	if (!fh_desc || !fh_desc->addr)
		return fsalstat(ERR_FSAL_FAULT, 0);

	switch (output_type) {
	case FSAL_DIGEST_NFSV3:
#ifdef PROXY_HANDLE_MAPPING
		fhs = sizeof(ph->h23);
		data = &ph->h23;
		break;
#endif
	case FSAL_DIGEST_NFSV4:
		fhs = ph->blob.len;
		data = &ph->blob;
		break;
	default:
		return fsalstat(ERR_FSAL_SERVERFAULT, 0);
	}

	if (fh_desc->len < fhs)
		return fsalstat(ERR_FSAL_TOOSMALL, 0);
	memcpy(fh_desc->addr, data, fhs);
	fh_desc->len = fhs;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static void fs_handle_to_key(struct fsal_obj_handle *obj_hdl,
			      struct gsh_buffdesc *fh_desc)
{
	struct fs_obj_handle *ph =
	    container_of(obj_hdl, struct fs_obj_handle, obj);
	fh_desc->addr = &ph->blob;
	fh_desc->len = ph->blob.len;
}

static void fs_hdl_release(struct fsal_obj_handle *obj_hdl)
{
	struct fs_obj_handle *ph =
	    container_of(obj_hdl, struct fs_obj_handle, obj);

	fsal_obj_handle_uninit(obj_hdl);

	gsh_free(ph);
}

/*
 * Without name the 'open' for NFSv4 makes no sense - we could
 * send a getattr to the backend server but it's not going to
 * do anything useful anyway, so just save the openflags to record
 * the fact that file has been 'opened' and be done.
 */
static fsal_status_t fs_open(struct fsal_obj_handle *obj_hdl,
			      fsal_openflags_t openflags)
{
	struct fs_obj_handle *ph;

	if (!obj_hdl)
		return fsalstat(ERR_FSAL_FAULT, EINVAL);

	ph = container_of(obj_hdl, struct fs_obj_handle, obj);
	if ((ph->openflags != FSAL_O_CLOSED) && (ph->openflags != openflags))
		return fsalstat(ERR_FSAL_FILE_OPEN, EBADF);
	ph->openflags = openflags;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static fsal_openflags_t
fs_status(struct fsal_obj_handle *obj_hdl)
{
	struct fs_obj_handle *ph;

	if (!obj_hdl)
		return FSAL_O_CLOSED;

	ph = container_of(obj_hdl, struct fs_obj_handle, obj);
	return ph->openflags;
}

static fsal_status_t fs_read(struct fsal_obj_handle *obj_hdl,
			      uint64_t offset, size_t buffer_size, void *buffer,
			      size_t *read_amount, bool *end_of_file)
{
	int rc;
	struct fs_obj_handle *ph;
	READ4resok *rok;

	if (!buffer_size) {
		*read_amount = 0;
		*end_of_file = false;
		return fsalstat(ERR_FSAL_NO_ERROR, 0);
	}

	ph = container_of(obj_hdl, struct fs_obj_handle, obj);
#if 0
	if ((ph->openflags & (FSAL_O_RDONLY | FSAL_O_RDWR)) == 0)
		return fsalstat(ERR_FSAL_FILE_OPEN, EBADF);
#endif

	if (buffer_size >
	    op_ctx->fsal_export->ops->fs_maxread(op_ctx->fsal_export))
		buffer_size =
		    op_ctx->fsal_export->ops->fs_maxread(op_ctx->fsal_export);

        tc_reset_compound(true);
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);
	rok = &resoparray[opcnt].nfs_resop4_u.opread.READ4res_u.resok4;
	rok->data.data_val = buffer;
	rok->data.data_len = buffer_size;
	COMPOUNDV4_ARG_ADD_OP_READ(opcnt, argoparray, offset, buffer_size);

	rc = fs_nfsv4_call(op_ctx->creds, NULL);
	if (rc != NFS4_OK)
		return nfsstat4_to_fsal(rc);

	*end_of_file = rok->eof;
	*read_amount = rok->data.data_len;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static fsal_status_t fs_write(struct fsal_obj_handle *obj_hdl,
			       uint64_t offset, size_t size, void *buffer,
			       size_t *write_amount, bool *fsal_stable)
{
	int rc;
	WRITE4resok *wok;
	struct fs_obj_handle *ph;

	if (!size) {
		*write_amount = 0;
		return fsalstat(ERR_FSAL_NO_ERROR, 0);
	}

	ph = container_of(obj_hdl, struct fs_obj_handle, obj);
#if 0
	if ((ph->openflags & (FSAL_O_WRONLY | FSAL_O_RDWR | FSAL_O_APPEND)) ==
	    0) {
		return fsalstat(ERR_FSAL_FILE_OPEN, EBADF);
	}
#endif

	if (size >
	    op_ctx->fsal_export->ops->fs_maxwrite(op_ctx->fsal_export))
		size =
		    op_ctx->fsal_export->ops->fs_maxwrite(op_ctx->fsal_export);

        tc_reset_compound(true);

	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);
	wok = &resoparray[opcnt].nfs_resop4_u.opwrite.WRITE4res_u.resok4;
	COMPOUNDV4_ARG_ADD_OP_WRITE(opcnt, argoparray, offset, buffer, size);

	rc = fs_nfsv4_call(op_ctx->creds, NULL);
	if (rc != NFS4_OK)
		return nfsstat4_to_fsal(rc);

	*write_amount = wok->count;
	*fsal_stable = false;

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

fsal_status_t fs_read_plus(struct fsal_obj_handle *obj_hdl,
                            uint64_t offset, size_t buffer_size,
                            void *buffer, size_t *read_amount,
                            bool *end_of_file,
                            struct io_info *info)
{
        int rc;
        struct fs_obj_handle *ph;
        READ_PLUS4res *rp4res;
        read_plus_res4 *rpr4;
        size_t pi_data_len = 0;

        offset = io_info_to_offset(info);
        buffer_size = io_info_to_file_dlen(info);
        pi_data_len = io_info_to_pi_dlen(info);

        if (!buffer_size && !pi_data_len) {
                *read_amount = 0;
                *end_of_file = false;
                return fsalstat(ERR_FSAL_NO_ERROR, 0);
        }

        ph = container_of(obj_hdl, struct fs_obj_handle, obj);

        if (buffer_size >
                op_ctx->fsal_export->ops->fs_maxread(op_ctx->fsal_export))
                buffer_size =
                      op_ctx->fsal_export->ops->fs_maxread(op_ctx->fsal_export);

        tc_reset_compound(true);
        COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);
        rp4res = &resoparray[opcnt].nfs_resop4_u.opread_plus;
        rpr4 = &rp4res->rpr_resok4;
        rpr4->rpr_contents_len = 1;
        rpr4->rpr_contents_val = &info->io_content;
        COMPOUNDV4_ARG_ADD_OP_READ_PLUS(opcnt, argoparray, offset,
                                        buffer_size, info->io_content.what);

	rc = fs_nfsv4_call(op_ctx->creds, NULL);
	if (rc != NFS4_OK)
                return nfsstat4_to_fsal(rc);

        // TODO: add sanity check of returned io_info

        *end_of_file = rpr4->rpr_eof;
        *read_amount = io_info_to_file_dlen(info);
        return nfsstat4_to_fsal(rp4res->rpr_status);
}

fsal_status_t fs_write_plus(struct fsal_obj_handle *obj_hdl,
			     uint64_t offset, size_t size,
			     void *buffer, size_t *write_amount,
			     bool *fsal_stable,
                             struct io_info *info)
{
	int rc;
	struct fs_obj_handle *ph;
        WRITE_PLUS4res *wp4res;
        write_response4 *wpr4;

	if (!size) {
		*write_amount = 0;
		return fsalstat(ERR_FSAL_NO_ERROR, 0);
	}

	ph = container_of(obj_hdl, struct fs_obj_handle, obj);
#if 0
	if ((ph->openflags & (FSAL_O_WRONLY | FSAL_O_RDWR | FSAL_O_APPEND)) ==
	    0) {
		return fsalstat(ERR_FSAL_FILE_OPEN, EBADF);
	}
#endif

	if (size > op_ctx->fsal_export->ops->fs_maxwrite(op_ctx->fsal_export))
                size =
                    op_ctx->fsal_export->ops->fs_maxwrite(op_ctx->fsal_export);

        tc_reset_compound(true);
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);

        wp4res = &resoparray[opcnt].nfs_resop4_u.opwrite_plus;
        wpr4 = &wp4res->WRITE_PLUS4res_u.wpr_resok4;
        COMPOUNDV4_ARG_ADD_OP_WRITE_PLUS(opcnt, argoparray, (&info->io_content));

	rc = fs_nfsv4_call(op_ctx->creds, NULL);
	if (rc != NFS4_OK)
		return nfsstat4_to_fsal(rc);

	*write_amount = wpr4->wr_count;
	*fsal_stable = wpr4->wr_committed != UNSTABLE4;
	return nfsstat4_to_fsal(wp4res->wpr_status);
}

/* We send all out writes as DATA_SYNC, commit becomes a NO-OP */
static fsal_status_t fs_commit(struct fsal_obj_handle *obj_hdl,
				off_t offset,
				size_t len)
{
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static fsal_status_t fs_close(struct fsal_obj_handle *obj_hdl)
{
	struct fs_obj_handle *ph;

	if (!obj_hdl)
		return fsalstat(ERR_FSAL_FAULT, EINVAL);

	ph = container_of(obj_hdl, struct fs_obj_handle, obj);
	if (ph->openflags == FSAL_O_CLOSED)
		return fsalstat(ERR_FSAL_NOT_OPENED, EBADF);
	ph->openflags = FSAL_O_CLOSED;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

void tc_attrs_to_fattr4(const struct tc_attrs *tca, fattr4 *attr4)
{
        struct attrlist attrlist = {0};

        if (tca->masks.has_mode) {
                attrlist.mask |= ATTR_MODE;
                attrlist.mask |= ATTR_TYPE;
                attrlist.mode = tca->mode;
        }
        if (tca->masks.has_size) {
                attrlist.mask |= ATTR_SIZE;
                attrlist.filesize = tca->size;
        }
        if (tca->masks.has_fileid) {
                attrlist.mask |= ATTR_FILEID;
                attrlist.fileid = tca->fileid;
        }
        if (tca->masks.has_blocks) {
                attrlist.mask |= ATTR_SPACEUSED;
                attrlist.spaceused = tca->blocks * 512;
        }
        if (tca->masks.has_uid) {
                attrlist.mask |= ATTR_OWNER;
                attrlist.owner = tca->uid;
        }
        if (tca->masks.has_gid) {
                attrlist.mask |= ATTR_GROUP;
                attrlist.group = tca->gid;
        }
        if (tca->masks.has_rdev) {
                attrlist.mask |= ATTR_RAWDEV;
                attrlist.rawdev.major = major(tca->rdev);
                attrlist.rawdev.minor = minor(tca->rdev);
        }
        if (tca->masks.has_atime) {
                attrlist.mask |= ATTR_ATIME;
                attrlist.atime = tca->atime;
        }
        if (tca->masks.has_mtime) {
                attrlist.mask |= ATTR_MTIME;
                attrlist.mtime = tca->mtime;
        }
        if (tca->masks.has_ctime) {
                attrlist.mask |= ATTR_CTIME;
                attrlist.ctime = tca->ctime;
        }

        if (fs_fsalattr_to_fattr4(&attrlist, attr4) != 0) {
                NFS4_ERR("cannot encode NFS attributes");
                assert(false);
        }
}

/**
 * Set mode bits about file type.
 *
 * See http://lxr.free-electrons.com/source/include/uapi/linux/stat.h
 *     stat(2)
 */
static void set_mode_type(mode_t *mode, object_file_type_t type)
{
        *mode &= ~S_IFMT;
	switch (type) {
	case REGULAR_FILE:
		*mode |= S_IFREG;
		break;
	case DIRECTORY:
		*mode |= S_IFDIR;
		break;
        case CHARACTER_FILE:
                *mode |= S_IFCHR;
                break;
        case BLOCK_FILE:
                *mode |= S_IFBLK;
                break;
        case SYMBOLIC_LINK:
                *mode |= S_IFLNK;
                break;
        case SOCKET_FILE:
                *mode |= S_IFSOCK;
                break;
        case FIFO_FILE:
                *mode |= S_IFIFO;
                break;
        default:
                NFS4_ERR("unsupported type: %d", type);
	}
}

void fattr4_to_tc_attrs(const fattr4 *attr4, struct tc_attrs *tca)
{
        struct attrlist attrlist;

        /* FIXME: void the const cast */
	if (nfs4_Fattr_To_FSAL_attr(&attrlist, (fattr4 *)attr4, NULL) !=
	    NFS4_OK) {
		NFS4_ERR("cannot decode NFS attributes");
                assert(false);
        }

        memset(&tca->masks, sizeof(tca->masks), 0);
        if (attrlist.mask & ATTR_MODE) {
                tca->masks.has_mode = true;
                tca->mode = attrlist.mode;
        }
        if (attrlist.mask & ATTR_SIZE) {
                tca->masks.has_size = true;
                tca->size = attrlist.filesize;
        }
        if (attrlist.mask & ATTR_NUMLINKS) {
                tca->masks.has_nlink = true;
                tca->nlink = attrlist.numlinks;
        }
        if (attrlist.mask & ATTR_OWNER) {
                tca->masks.has_uid = true;
                tca->uid = attrlist.owner;
        }
        if (attrlist.mask & ATTR_FILEID) {
		tc_attrs_set_fileid(tca, attrlist.fileid);
	}
        if (attrlist.mask & ATTR_GROUP) {
                tca->masks.has_gid = true;
                tca->gid = attrlist.group;
        }
        if (attrlist.mask & ATTR_RAWDEV) {
                tca->masks.has_rdev = true;
		tca->rdev =
		    makedev(attrlist.rawdev.major, attrlist.rawdev.minor);
	}
        if (attrlist.mask & ATTR_ATIME) {
                tca->masks.has_atime = true;
                tca->atime = attrlist.atime;
        }
        if (attrlist.mask & ATTR_MTIME) {
                tca->masks.has_mtime = true;
                tca->mtime = attrlist.mtime;
        }
        if (attrlist.mask & ATTR_CTIME) {
                tca->masks.has_ctime = true;
                tca->ctime = attrlist.ctime;
        }
        if (attrlist.mask & ATTR_SPACEUSED) {
                tca->masks.has_blocks = true;
                tca->blocks = attrlist.spaceused / 512;
        }

        set_mode_type(&tca->mode, attrlist.type);
}

static bool tc_open_file_if_necessary(const tc_file *tcf, int flags,
				      buf_t *pbuf_owner, fattr4 *attrs4,
				      const tc_file **opened_file)
{
	slice_t name;
	struct tc_attrs attrs;

        if (tcf->type == TC_FILE_DESCRIPTOR) {
		tc_prepare_putfh(((struct nfs4_fd_data *)tcf->fd_data)->fh4);
                return false;
        }

	if (tcf->type == TC_FILE_CURRENT &&
	    (tcf->path == NULL || strcmp(tcf->path, ".") == 0)) {
		return false; /* no need to open */
	}

	if (*opened_file) {
		if (tc_cmp_file(tcf, *opened_file)) {
			return false; /* no need to open */
		}
		COMPOUNDV4_ARG_ADD_OP_CLOSE_NOSTATE(opcnt, argoparray);
	}

        tc_set_current_fh(tcf, &name, true);

	if (flags & O_CREAT) {
		attrs.masks = TC_ATTRS_MASK_NONE;
		tc_attrs_set_mode(&attrs, 0644);
		tc_attrs_set_uid(&attrs, getuid());
		tc_attrs_set_gid(&attrs, getgid());
		tc_attrs_to_fattr4(&attrs, attrs4);
	} else {
		attrs4 = NULL;
	}
	tc_prepare_open(name, flags, pbuf_owner, attrs4);

	*opened_file = tcf;
	return true;
}

static tc_res tc_nfs4_openv(struct tc_attrs *attrs, int count, int *flags,
			    stateid4 *sids)
{
	int rc;
	tc_res tcres;
	nfsstat4 op_status;
	int i = 0; /* index of tc_iovec */
	int j = 0; /* index of NFS operations */
	slice_t name;
	fattr4 *fattrs;
	char *fattr_blobs; /* an array of FATTR_BLOB_SZ-sized buffers */
	char *fh_buffers;
	nfs_fh4 fh;
	OPEN4resok *opok;

	NFS4_DEBUG("tc_nfs4_openv");
	assert(count >= 1);
        tc_reset_compound(true);
	fattrs = alloca(count * sizeof(fattr4));
	memset(fattrs, 0, count * sizeof(fattr4));
	fattr_blobs = (char *)alloca(count * FATTR_BLOB_SZ);
	fh_buffers = alloca(count * NFS4_FHSIZE); /* on stack */

	for (i = 0; i < count; ++i) {
		rc = tc_set_current_fh(&attrs[i].file, &name, true);
		if (rc < 0) {
                        tcres = tc_failure(i, ERR_FSAL_INVAL);
                        goto exit;
                }
		if (flags[i] & O_CREAT) {
                        /* bit-and umask with mode */
			tc_attrs_to_fattr4(&attrs[i], &fattrs[i]);
		}
		tc_prepare_open(name, flags[i], new_auto_buf(64), &fattrs[i]);
		tc_prepare_getfh(fh_buffers + i * NFS4_FHSIZE);
		tc_prepare_getattr(fattr_blobs + i * FATTR_BLOB_SZ,
				   &fs_bitmap_getattr);
	}

	rc = fs_nfsv4_call(op_ctx->creds, &tcres.err_no);
	if (rc != RPC_SUCCESS) {
                NFS4_ERR("rpc failed: %d", rc);
                tcres = tc_failure(0, rc);
                goto exit;
        }

        i = 0;
        for (j = 0; j < opcnt; ++j) {
                op_status = get_nfs4_op_status(resoparray + j);
                if (op_status != NFS4_OK) {
                        NFS4_ERR("NFS operation (%d) failed: %d",
                                 resoparray[j].resop, op_status);
                        tcres = tc_failure(i, nfsstat4_to_errno(op_status));
                        goto exit;
                }
                switch(resoparray[j].resop) {
                case NFS4_OP_OPEN:
			opok = &resoparray[j]
				    .nfs_resop4_u.opopen.OPEN4res_u.resok4;
			flags[i] = opok->rflags;
                        copy_stateid4(&sids[i], &opok->stateid);
			break;
                case NFS4_OP_GETFH:
			tc_file_set_handle(&attrs[i].file,
					   &resoparray[j]
						.nfs_resop4_u.opgetfh
						.GETFH4res_u.resok4.object);
			break;
                case NFS4_OP_GETATTR:
			fattr4_to_tc_attrs(
			    &resoparray[j]
				 .nfs_resop4_u.opgetattr.GETATTR4res_u.resok4
				 .obj_attributes,
			    attrs + i);
			++i;
			break;
                }
        }

exit:
        for (i = 0; i < count; ++i) {
                nfs4_Fattr_Free(&fattrs[i]);
        }
        return tcres;
}

static tc_res tc_nfs4_closev(const nfs_fh4 *fh4s, int count, stateid4 *sids,
			     seqid4 *seqs)
{
        int i;
	int rc;
	tc_res tcres = { .err_no = 0 };

	NFS4_DEBUG("tc_nfs4_closev");
	assert(count >= 1);
        tc_reset_compound(true);

	for (i = 0; i < count; ++i) {
		// ignore stateless open
                if (!is_special_stateid(sids + i)) {
			COMPOUNDV4_ARG_ADD_OP_PUTFH(
			    opcnt, argoparray, fh4s[i]);
			COMPOUNDV4_ARG_ADD_OP_TCCLOSE(opcnt,
						      argoparray,
						      seqs[i], sids[i]);
		}
        }

	rc = fs_nfsv4_call(op_ctx->creds, NULL);
	if (rc != NFS4_OK) {
                NFS4_ERR("rpc failed: %d", rc);
                tcres = tc_failure(0, rc);
                goto exit;
        }

        for (i = 0; i < count; ++i) {
                sids[i].seqid++;
        }

exit:
        return tcres;
}

static tc_res tc_nfs4_lgetattrsv(struct tc_attrs *attrs, int count)
{
        int rc;
        tc_res tcres;
	nfsstat4 op_status;
	GETATTR4resok *atok;
        slice_t name;
	int i = 0;      /* index of tc_iovec */
	int j = 0;      /* index of NFS operations */
	char *fattr_blobs; /* an array of FATTR_BLOB_SZ-sized buffers */
        struct bitmap4 *bitmaps;

        NFS4_DEBUG("tc_nfs4_lgetattrsv");
        assert(count >= 1);
        tc_reset_compound(true);
        fattr_blobs = (char *)malloc(count * FATTR_BLOB_SZ);
        assert(fattr_blobs);
	bitmaps = alloca(count * sizeof(*bitmaps));

	for (i = 0; i < count; ++i) {
		rc = tc_set_current_fh(&attrs[i].file, &name, true);
		if (rc < 0) {
                        tcres = tc_failure(i, ERR_FSAL_INVAL);
                        goto exit;
                }
                if (name.size != 0) {
                        tc_prepare_lookups(&name, 1);
                }
		tc_attr_masks_to_bitmap(&attrs[i].masks, bitmaps + i);
		tc_prepare_getattr(fattr_blobs + i * FATTR_BLOB_SZ,
				   bitmaps + i);
	}

	rc = fs_nfsv4_call(op_ctx->creds, &tcres.err_no);
	if (rc != RPC_SUCCESS) {
                NFS4_ERR("rpc failed: %d", rc);
                tcres = tc_failure(0, rc);
                goto exit;
        }

        i = 0;
	for (j = 0; j < opcnt; ++j) {
                op_status = get_nfs4_op_status(&resoparray[j]);
                if (op_status != NFS4_OK) {
			NFS4_ERR("NFS operation (%d) failed: %d",
				 resoparray[j].resop, op_status);
			tcres = tc_failure(i, nfsstat4_to_errno(op_status));
                        goto exit;
                }
                if (resoparray[j].resop != NFS4_OP_GETATTR)
                        continue;
		atok =
		    &resoparray[j].nfs_resop4_u.opgetattr.GETATTR4res_u.resok4;
		fattr4_to_tc_attrs(&atok->obj_attributes, attrs + i);
		++i;
	}

exit:
        free(fattr_blobs);
        return tcres;
}

static tc_res tc_nfs4_lsetattrsv(struct tc_attrs *attrs, int count)
{
        int rc;
        tc_res tcres;
	nfsstat4 op_status;
	fattr4 *new_fattrs;
	int i = 0;      /* index of tc_iovec */
	int j = 0;      /* index of NFS operations */
        fattr4 *fattrs; /* input attrs to set */
	char *fattr_blobs; /* an array of FATTR_BLOB_SZ-sized buffers */
        struct bitmap4 *bitmaps;
        slice_t name;

        NFS4_DEBUG("tc_nfs4_lsetattrsv");
        tc_reset_compound(true);
	fattrs = alloca(count * sizeof(fattr4));           /* on stack */
        fattr_blobs = alloca(count * FATTR_BLOB_SZ);
	bitmaps = alloca(count * sizeof(*bitmaps));

	for (i = 0; i < count; ++i) {
                tc_attrs_to_fattr4(&attrs[i], &fattrs[i]);
                rc = tc_set_current_fh(&attrs[i].file, &name, true);
                if (rc < 0) {
                        tcres = tc_failure(i, ERR_FSAL_INVAL);
                        goto exit;
                }
                if (name.size != 0) {
                        tc_prepare_lookups(&name, 1);
                }
                tc_prepare_setattr(&fattrs[i]);
		tc_attr_masks_to_bitmap(&attrs[i].masks, bitmaps + i);
		tc_prepare_getattr(fattr_blobs + i * FATTR_BLOB_SZ,
				   bitmaps + i);
	}

	rc = fs_nfsv4_call(op_ctx->creds, &tcres.err_no);
	if (rc != RPC_SUCCESS) {
                NFS4_ERR("rpc failed: %d", rc);
                tcres = tc_failure(0, rc);
                goto exit;
        }

        i = 0;
        for (j = 0; j < opcnt; ++j) {
                op_status = get_nfs4_op_status(&resoparray[j]);
                if (op_status != NFS4_OK) {
			NFS4_ERR("NFS operation (%d) failed: %d",
				 resoparray[j].resop, op_status);
			tcres = tc_failure(i, nfsstat4_to_errno(op_status));
                        goto exit;
                }
                switch (resoparray[j].resop) {
                case NFS4_OP_SETATTR:
                        NFS4_DEBUG("LSETATTR at %d succeeded", j);
                        break;
                case NFS4_OP_GETATTR:
			new_fattrs = &resoparray[j]
					  .nfs_resop4_u.opgetattr.GETATTR4res_u
					  .resok4.obj_attributes;
			fattr4_to_tc_attrs(new_fattrs, attrs + i);
                        ++i;
                        break;
                }
        }

exit:
        for (i = 0; i < count; ++i) {
                nfs4_Fattr_Free(fattrs + i);
        }
        return tcres;
}

/**
 * In case of partial failure the file_handle of succeeded files should be
 * freed by callers.
 */
static tc_res tc_nfs4_mkdirv(struct tc_attrs *dirs, int count)
{
        int i;
        int j;
        int rc;
        tc_res tcres;
        nfsstat4 op_status;
        char *fh_buffers;
        fattr4 *input_attrs;
        char *fattr_blobs;
	GETATTR4resok *atok;
        slice_t name;

        /* allocate space */
        NFS4_DEBUG("making %d directories", count);
        assert(count >= 1);
        tc_reset_compound(true);
	input_attrs = alloca(count * sizeof(fattr4));   /* on stack */
        memset(input_attrs, 0, count * sizeof(fattr4));
	fattr_blobs = alloca(count * FATTR_BLOB_SZ);    /* on stack */
        fh_buffers = alloca(count * NFS4_FHSIZE);       /* on stack */

        /* prepare compound requests */
        for (i = 0; i < count; ++i) {
                tc_attrs_to_fattr4(&dirs[i], &input_attrs[i]);
		rc = tc_set_current_fh(&dirs[i].file, &name, true);
		if (rc < 0) {
                        tcres = tc_failure(i, ERR_FSAL_INVAL);
                        goto exit;
                }

		tc_prepare_mkdir(name.data, &input_attrs[i]);

		tc_prepare_getfh(fh_buffers + i * NFS4_FHSIZE);

		tc_prepare_getattr(fattr_blobs + i * FATTR_BLOB_SZ,
                                   &fs_bitmap_getattr);
	}

	rc = fs_nfsv4_call(op_ctx->creds, &tcres.err_no);
	if (rc != RPC_SUCCESS) {
                NFS4_ERR("rpc failed: %d", rc);
                tcres = tc_failure(0, rc);
                goto exit;
        }

        i = 0;
        for (j = 0; j < opcnt; ++j) {
                op_status = get_nfs4_op_status(resoparray + j);
                if (op_status != NFS4_OK) {
                        NFS4_ERR("NFS operation (%d) failed: %d",
                                 resoparray[j].resop, op_status);
                        tcres = tc_failure(i, nfsstat4_to_errno(op_status));
                        goto exit;
                }
                switch(resoparray[j].resop) {
                case NFS4_OP_CREATE:
                        ++i;
                        break;
                case NFS4_OP_GETFH:
			tc_file_set_handle(&dirs[i - 1].file,
					   &resoparray[j]
						.nfs_resop4_u.opgetfh
						.GETFH4res_u.resok4.object);
			break;
                case NFS4_OP_GETATTR:
			atok =
			    &resoparray[j]
				 .nfs_resop4_u.opgetattr.GETATTR4res_u.resok4;
			fattr4_to_tc_attrs(&atok->obj_attributes, dirs + i - 1);
                        break;
                }
        }

exit:
        for (i = 0; i < count; ++i) {
                nfs4_Fattr_Free(input_attrs + i);
        }
        return tcres;
}

/**
 * A directory to be listed.
 */
struct tc_dir_to_list {
	struct glist_head list; /* list of all directories to be listed */
	const char *path;  /* relative path from the original dir */
        nfs_cookie4 cookie;
        char fhbuf[NFS4_FHSIZE];
        nfs_fh4 fh;
	int origin_index; /* index of the dir that this dir originate from */
	int nchildren;
        bool need_free_path;
};

struct nfsoparray {
        nfs_argop4 *argoparray;
        nfs_resop4 *resoparray;
        int opcnt;
        int capacity;
};

static bool xdr_listdirv(XDR *x, struct nfsoparray *nfsops)
{
        int i;
        bool res = true;

        for (i = 0; i < nfsops->opcnt && res; ++i) {
                if (nfsops->resoparray[i].resop == NFS4_OP_READDIR) {
                        res = xdr_nfs_resop4(x, nfsops->resoparray + i);
                }
        }

        return res;
}

static inline struct tc_dir_to_list *
enqueue_dir_to_list(struct glist_head *dir_queue, const char *path, int index,
		    bool own_path)
{
	struct tc_dir_to_list *dle;

	dle = malloc(sizeof(*dle));
	dle->path = path;
	dle->need_free_path = own_path;
	dle->cookie = 0;
	dle->fh.nfs_fh4_val = NULL;
	dle->fh.nfs_fh4_len = 0;
	dle->origin_index = index;
	dle->nchildren = 0;
	glist_add_tail(dir_queue, &dle->list);

	return dle;
}

static inline void dequeue_dir_to_list(struct glist_head *dir_queue)
{
	struct tc_dir_to_list *dle;

	dle = glist_first_entry(dir_queue, struct tc_dir_to_list, list);
	glist_del(&dle->list);
	if (dle->need_free_path) {
		free((char *)dle->path);
	}
	free(dle);
}

static int tc_parse_dir_entries(struct glist_head *dir_queue,
				struct tc_dir_to_list *parent,
				const entry4 *entries, int *limit,
                                bool recursive, bool has_mode,
                                tc_listdirv_cb cb, void *cbarg)
{
	bool success;
	char *path;
	buf_t buf;
	int ret;
	struct tc_attrs attrs;
	int n = 0;
        TC_DECLARE_COUNTER(listdircb);

	while (entries && (*limit == -1 || *limit > 0)) {
		path = malloc(PATH_MAX);
		buf = mkbuf(path, PATH_MAX);
		ret = tc_path_join_s(toslice(parent->path),
				     mkslice(entries->name.utf8string_val,
					     entries->name.utf8string_len),
				     &buf);
		assert(ret > 0);
		attrs.file = tc_file_from_path(asstr(&buf));
		fattr4_to_tc_attrs(&entries->attrs, &attrs);
                attrs.masks.has_mode = has_mode;

                TC_START_COUNTER(listdircb);
		success = cb(&attrs, parent->path, cbarg);
                TC_STOP_COUNTER(listdircb, 1, success);

		if (!success) {
			free(path);
			return -1;
		}

		if (recursive && S_ISDIR(attrs.mode)) {
			enqueue_dir_to_list(dir_queue, path,
					    parent->origin_index, true);
		} else {
                        free(path);
                }

		parent->cookie = entries->cookie;
		entries = entries->nextentry;
		++n;
		if (*limit != -1) {
			--*limit;
                }
	}
	return n;
}

static tc_res tc_do_listdirv(struct glist_head *dir_queue, int *limit,
                             struct tc_attrs_masks masks, bool recursive,
			     tc_listdirv_cb cb, void *cbarg)
{
	struct tc_dir_to_list *next_dle;
	struct tc_dir_to_list *dle;
	struct nfsoparray nfsops = { .argoparray = argoparray,
				     .resoparray = resoparray,
				     .opcnt = opcnt,
				     .capacity = MAX_NUM_OPS_PER_COMPOUND, };
	tc_res tcres;
	nfsstat4 op_status;
	READDIR4resok *rdok;
	int i = 0, j;
	int rc;
	static const int MAX_READDIRS_PER_COMPOUND = 16;
        bool has_mode = masks.has_mode;
        bitmap4 bitmap = fs_bitmap_readdir;
        bool incomplete = false;
        slice_t name;

	tc_reset_compound(true);

        masks.has_mode = true;  // to detect directory
        tc_attr_masks_to_bitmap(&masks, &bitmap);

	glist_for_each_entry(dle, dir_queue, list)
	{
		if (dle->fh.nfs_fh4_len == 0) {
			tc_set_cfh_to_path(dle->path, &name, true);
                        tc_prepare_lookups(&name, 1);
			tc_prepare_getfh(dle->fhbuf);
		} else {
			tc_prepare_putfh(&dle->fh);
		}
		tc_prepare_readdir(&dle->cookie, &bitmap);
		if (++i >= MAX_READDIRS_PER_COMPOUND)
			break;
	}

	rc = fs_nfsv4_call(op_ctx->creds, &tcres.err_no);
	if (rc != RPC_SUCCESS) {
		NFS4_ERR("rpc failed: %d", rc);
		tcres = tc_failure(0, rc);
		goto exit;
	}

	dle = glist_first_entry(dir_queue, struct tc_dir_to_list, list);
	i = 0;
	for (j = 0; j < opcnt; ++j) {
		op_status = get_nfs4_op_status(resoparray + j);
		if (op_status != NFS4_OK) {
			NFS4_ERR("NFS operation (%d) failed: %d",
				 resoparray[j].resop, op_status);
			tcres = tc_failure(i, nfsstat4_to_errno(op_status));
			goto exit;
		}
		switch (resoparray[j].resop) {
		case NFS4_OP_GETFH:
			dle->fh =
			    resoparray[j]
				.nfs_resop4_u.opgetfh.GETFH4res_u.resok4.object;
			break;
		case NFS4_OP_READDIR:
                        /* To avoid out-of-order callbacks, we stop processing
                         * the directories after the first incomplete directory
                         * in the compound. */
                        if (incomplete) break;
			rdok =
			    &resoparray[j]
				 .nfs_resop4_u.opreaddir.READDIR4res_u.resok4;
			rc = tc_parse_dir_entries(
			    dir_queue, dle, rdok->reply.entries, limit,
			    recursive, has_mode, cb, cbarg);
			if (rc < 0) {
				tcres = tc_failure(i, rc);
				goto exit;
			}
			dle->nchildren += rc;
			++i;
			next_dle = glist_next_entry(dle, list);
			if (rdok->reply.eof) {
				glist_del(&dle->list);
				if (dle->need_free_path) {
					free((char *)dle->path);
				}
				free(dle);
			} else {
				incomplete = true;
			}
			dle = next_dle;
                        if (*limit == 0) {
                                tcres.err_no = 0;
                                goto exit;
                        }
			break;
		}
	}

exit:
	nfsops.opcnt = opcnt;
	xdr_free((xdrproc_t)xdr_listdirv, &nfsops);
	return tcres;
}

tc_res tc_nfs4_listdirv(const char **dirs, int count,
			struct tc_attrs_masks masks, int max_entries,
			bool recursive, tc_listdirv_cb cb, void *cbarg)
{
        int i = 0;
	tc_res tcres = { .err_no = 0 };
	GLIST_HEAD(dir_queue);

        /**
         * The API uses "0" as "unlimited" whereas the implementation uses "-1"
         * as "unlimited".
         */
        if (max_entries == 0) {
                max_entries = -1;
        }

        for (i = 0; i < count; ++i) {
		enqueue_dir_to_list(&dir_queue, dirs[i], i, false);
	}

	/**
         * We maintain a queue of directories to list, and call
         * tc_do_listdirv() for each directory.  Once the EOF is reached for a
         * directory, we dequeue the directory until the queue becomes empty.
         * When "recursive" is true, a subdirectory is enqueued whenever we
         * encounter the subdirectory.
         */
	while (!glist_empty(&dir_queue)) {
		tcres = tc_do_listdirv(&dir_queue, &max_entries, masks,
				       recursive, cb, cbarg);
		if (!tc_okay(tcres)) {
			goto exit;
		}
	}

exit:
        while (!glist_empty(&dir_queue)) {
                dequeue_dir_to_list(&dir_queue);
	}
	return tcres;
}

static tc_res tc_nfs4_renamev(tc_file_pair *pairs, int count)
{
	int rc;
	tc_res tcres;
	nfsstat4 op_status;
	int i = 0;      /* index of tc_iovec */
	int j = 0;      /* index of NFS operations */
        slice_t srcname;
        slice_t dstname;

        NFS4_DEBUG("tc_nfs4_renamev");
        tc_reset_compound(true);

        for (i = 0; i < count; ++i) {
                rc = tc_set_saved_fh(&pairs[i].src_file, &srcname);
                if (rc < 0) {
                        tcres = tc_failure(i, ERR_FSAL_INVAL);
                        goto exit;
                }
                rc = tc_set_current_fh(&pairs[i].dst_file, &dstname, false);
                if (rc < 0) {
                        tcres = tc_failure(i, ERR_FSAL_INVAL);
                        goto exit;
                }
                tc_prepare_rename(&srcname, &dstname);
        }

        rc = fs_nfsv4_call(op_ctx->creds, &tcres.err_no);
        if (rc != RPC_SUCCESS) {
                NFS4_ERR("rpc failed: %d", rc);
                tcres = tc_failure(0, rc);
                goto exit;
        }

        i = 0;
        for (j = 0; j < opcnt; ++j) {
                op_status = get_nfs4_op_status(&resoparray[j]);
                if (op_status != NFS4_OK) {
			NFS4_ERR("NFS operation (%d) failed: %d",
				 resoparray[j].resop, op_status);
			tcres = tc_failure(i, nfsstat4_to_errno(op_status));
                        goto exit;
                }
                if (resoparray[j].resop == NFS4_OP_RENAME) {
                        ++i;
                }
        }

exit:
        return tcres;
}

static tc_res tc_nfs4_removev(tc_file *files, int count)
{
        int rc;
        tc_res tcres;
	nfsstat4 op_status;
	int i = 0;      /* index of tc_iovec */
	int j = 0;      /* index of NFS operations */
        slice_t name;

        NFS4_DEBUG("tc_nfs4_removev");
        tc_reset_compound(true);

        for (i = 0; i < count; ++i) {
                rc = tc_set_current_fh(&files[i], &name, true);
                if (rc < 0) {
                        tcres = tc_failure(i, ERR_FSAL_INVAL);
                        goto exit;
                }
                tc_prepare_remove(new_auto_str(name));
        }

	rc = fs_nfsv4_call(op_ctx->creds, &tcres.err_no);
	if (rc != RPC_SUCCESS) {
                NFS4_ERR("rpc failed: %d", rc);
                tcres = tc_failure(0, rc);
                goto exit;
        }

        i = 0;
        for (j = 0; j < opcnt; ++j) {
                op_status = get_nfs4_op_status(&resoparray[j]);
                if (op_status != NFS4_OK) {
			NFS4_ERR("NFS operation (%d) failed: %d",
				 resoparray[j].resop, op_status);
			tcres = tc_failure(i, nfsstat4_to_errno(op_status));
                        goto exit;
                }
                if (resoparray[j].resop == NFS4_OP_REMOVE) {
                        ++i;
                }
        }

exit:
        return tcres;
}

static tc_res tc_nfs4_copyv(struct tc_extent_pair *pairs, int count)
{
	int rc;
	tc_res tcres;
	nfsstat4 op_status;
	int i = 0; /* index of tc_iovec */
	int j = 0; /* index of NFS operations */
	slice_t srcname;
	slice_t dstname;
        struct tc_attrs tca;
        fattr4 *attrs4;

	NFS4_DEBUG("tc_nfs4_copyv");
        attrs4 = calloc(count, sizeof(*attrs4));
        assert(attrs4);

        tc_reset_compound(true);
	for (i = 0; i < count; ++i) {
		tc_set_cfh_to_path(pairs[i].src_path, &srcname, false);
		tc_prepare_open(srcname, O_RDONLY, new_auto_buf(64),
				NULL);
                tc_prepare_savefh(NULL);

		tc_set_cfh_to_path(pairs[i].dst_path, &dstname, false);
                tc_set_up_creation(&tca, new_auto_str(dstname), 0755);
		tc_attrs_to_fattr4(&tca, &attrs4[i]);
		tc_prepare_open(dstname, O_WRONLY | O_CREAT,
				new_auto_buf(64), &attrs4[i]);

		tc_prepare_copy(pairs[i].src_offset,
				pairs[i].dst_offset, pairs[i].length);

		COMPOUNDV4_ARG_ADD_OP_CLOSE_NOSTATE(opcnt,
						    argoparray);
                tc_prepare_restorefh();
		COMPOUNDV4_ARG_ADD_OP_CLOSE_NOSTATE(opcnt,
						    argoparray);
	}

	rc = fs_nfsv4_call(op_ctx->creds, &tcres.err_no);
	if (rc != RPC_SUCCESS) {
                NFS4_ERR("rpc failed: %d", rc);
                tcres = tc_failure(0, rc);
                goto exit;
        }

	i = 0;
	for (j = 0; j < opcnt; ++j) {
		op_status = get_nfs4_op_status(&resoparray[j]);
		if (op_status != NFS4_OK) {
			NFS4_ERR("NFS operation (%d) failed: %d",
				 resoparray[j].resop, op_status);
			tcres = tc_failure(i, nfsstat4_to_errno(op_status));
			goto exit;
		}
		if (resoparray[j].resop == NFS4_OP_COPY) {
			pairs[i].length =
			    resoparray[j]
				.nfs_resop4_u.opcopy.COPY4res_u.cr_bytes_copied;
			++i;
		}
	}

exit:
	for (i = 0; i < count; ++i) {
		nfs4_Fattr_Free(&attrs4[i]);
	}
	free(attrs4);
	return tcres;
}

static tc_res tc_nfs4_symlinkv(const char **oldpaths, const char **newpaths,
			       int count)
{
	int rc;
	tc_res tcres;
	nfsstat4 op_status;
	int i = 0; /* index of tc_iovec */
	int j = 0; /* index of NFS operations */
	struct tc_attrs tca;
	fattr4 *attrs4;
	slice_t name;
	char *pname;

	NFS4_DEBUG("tc_nfs4_symlinkv");
	attrs4 = calloc(count, sizeof(*attrs4));
	assert(attrs4);

	tc_reset_compound(true);
	for (i = 0; i < count; ++i) {
		tc_set_cfh_to_path(newpaths[i], &name, true);
		pname = new_auto_str(name);
		tc_set_up_creation(&tca, pname, 0755);
		tc_attrs_to_fattr4(&tca, &attrs4[i]);
		tc_prepare_symlink(pname, (char *)oldpaths[i], &attrs4[i]);
	}

	rc = fs_nfsv4_call(op_ctx->creds, &tcres.err_no);
	if (rc != RPC_SUCCESS) {
		NFS4_ERR("rpc failed: %d", rc);
		tcres = tc_failure(0, rc);
		goto exit;
	}

	i = 0;
	for (j = 0; j < opcnt; ++j) {
		op_status = get_nfs4_op_status(&resoparray[j]);
		if (op_status != NFS4_OK) {
			NFS4_ERR("NFS operation (%d) failed: %d",
				 resoparray[j].resop, op_status);
			tcres = tc_failure(i, nfsstat4_to_errno(op_status));
			goto exit;
		}
		if (resoparray[j].resop == NFS4_OP_CREATE) {
			++i;
		}
	}

exit:
	for (i = 0; i < count; ++i) {
		nfs4_Fattr_Free(&attrs4[i]);
	}
	free(attrs4);
	return tcres;
}

tc_res tc_nfs4_readlinkv(const char **paths, char **bufs, size_t *bufsizes,
			 int count)
{
	int rc;
        slice_t name;
	tc_res tcres;
	nfsstat4 op_status;
	size_t lksize;
	int i = 0; /* index of tc_iovec */
	int j = 0; /* index of NFS operations */

	NFS4_DEBUG("tc_nfs4_readlinkv");

	tc_reset_compound(true);
	for (i = 0; i < count; ++i) {
                tc_set_cfh_to_path(paths[i], &name, true);
                tc_prepare_lookups(&name, 1);
		tc_prepare_readlink(bufs[i], bufsizes[i]);
	}

	rc = fs_nfsv4_call(op_ctx->creds, &tcres.err_no);
	if (rc != RPC_SUCCESS) {
		NFS4_ERR("rpc failed: %d", rc);
		tcres = tc_failure(0, rc);
		goto exit;
	}

	i = 0;
	for (j = 0; j < opcnt; ++j) {
		op_status = get_nfs4_op_status(&resoparray[j]);
		if (op_status != NFS4_OK) {
			NFS4_ERR("NFS operation (%d) failed: %d",
				 resoparray[j].resop, op_status);
			tcres = tc_failure(i, nfsstat4_to_errno(op_status));
			goto exit;
		}
		if (resoparray[j].resop == NFS4_OP_READLINK) {
			lksize = resoparray[j]
				     .nfs_resop4_u.opreadlink.READLINK4res_u
				     .resok4.link.utf8string_len;
			if (lksize < bufsizes[i]) {
				bufs[i][lksize] = '\0';
				bufsizes[i] = lksize;
			}
			++i;
		}
	}

exit:
	return tcres;
}

static int tc_nfs4_chdir(const char *path)
{
	int rc;
	struct tc_cwd_data *cwd;
	GETFH4resok *fhok;

	NFS4_DEBUG("tc_nfs4_chdir");

	cwd = malloc(sizeof(*cwd));
	if (!cwd) {
		return -ENOMEM;
	}
	cwd->refcount = 1; // grap a refcount
        strncpy(cwd->path, path, PATH_MAX);

        tc_reset_compound(true);

        tc_set_cfh_to_path(path, NULL, true);
	fhok = tc_prepare_getfh(cwd->fhbuf);

	rc = fs_nfsv4_call(op_ctx->creds, NULL);
	if (rc != RPC_SUCCESS) {
		NFS4_ERR("rpc failed: %d", rc);
		free(cwd);
		return -rc;
	}

	cwd->fh = fhok->object;
        assert(cwd->fh.nfs_fh4_val == cwd->fhbuf);

	pthread_mutex_lock(&tc_cwd_lock);
	if (tc_cwd)
		tc_put_cwd(tc_cwd);
	tc_cwd = cwd;
	pthread_mutex_unlock(&tc_cwd_lock);

	return 0;
}

static char *tc_nfs4_getcwd()
{
	struct tc_cwd_data *cwd;
	char *path;

	cwd = tc_get_cwd();
	path = strdup(cwd->path);
	tc_put_cwd(cwd);

	return path;
}

void fs_handle_ops_init(struct fsal_obj_ops *ops)
{
	ops->release = fs_hdl_release;
	ops->lookup = fs_lookup;
	ops->lookup_plus = kernel_lookupplus;
	ops->readdir = fs_readdir;
	ops->create = fs_create;
	ops->mkdir = fs_mkdir;
	ops->mknode = fs_mknod;
	ops->symlink = fs_symlink;
	ops->readlink = fs_readlink;
	ops->getattrs = fs_getattrs;
	ops->setattrs = fs_setattrs;
	ops->link = fs_link;
	ops->rename = fs_rename;
	ops->unlink = fs_unlink;
	ops->open = fs_open;
	ops->read = fs_read;
	ops->write = fs_write;
        ops->read_plus = fs_read_plus;
        ops->write_plus = fs_write_plus;
	ops->commit = fs_commit;
	ops->close = fs_close;
	ops->handle_is = fs_handle_is;
	ops->handle_digest = fs_handle_digest;
	ops->handle_to_key = fs_handle_to_key;
	ops->status = fs_status;
	ops->tc_readv = tc_nfs4_readv;
	ops->tc_writev = tc_nfs4_writev;
        ops->tc_lgetattrsv = tc_nfs4_lgetattrsv;
        ops->tc_lsetattrsv = tc_nfs4_lsetattrsv;
        ops->tc_mkdirv = tc_nfs4_mkdirv;
        ops->tc_listdirv = tc_nfs4_listdirv;
        ops->tc_renamev = tc_nfs4_renamev;
        ops->tc_removev = tc_nfs4_removev;
        ops->tc_copyv = tc_nfs4_copyv;
        ops->tc_symlinkv = tc_nfs4_symlinkv;
        ops->tc_readlinkv = tc_nfs4_readlinkv;
        ops->tc_chdir = tc_nfs4_chdir;
        ops->tc_getcwd = tc_nfs4_getcwd;
	ops->tc_destroysession = fs_destroy_session;
	ops->root_lookup = fs_root_lookup;
        ops->tc_openv = tc_nfs4_openv;
        ops->tc_closev = tc_nfs4_closev;
}

#ifdef PROXY_HANDLE_MAPPING
static unsigned int hash_nfs_fh4(const nfs_fh4 *fh, unsigned int cookie)
{
	const char *cpt;
	unsigned int sum = cookie;
	unsigned int extract;
	unsigned int mod = fh->nfs_fh4_len % sizeof(unsigned int);

	for (cpt = fh->nfs_fh4_val;
	     cpt - fh->nfs_fh4_val < fh->nfs_fh4_len - mod;
	     cpt += sizeof(unsigned int)) {
		memcpy(&extract, cpt, sizeof(unsigned int));
		sum = (3 * sum + 5 * extract + 1999);
	}

	/*
	 * If the handle is not 32 bits-aligned, the last loop will
	 * get uninitialized chars after the end of the handle. We
	 * must avoid this by skipping the last loop and doing a
	 * special processing for the last bytes
	 */
	if (mod) {
		extract = 0;
		while (cpt - fh->nfs_fh4_val < fh->nfs_fh4_len) {
			extract <<= 8;
			extract |= (uint8_t) (*cpt++);
		}
		sum = (3 * sum + 5 * extract + 1999);
	}

	return sum;
}
#endif

static struct fs_obj_handle *fs_alloc_handle(struct fsal_export *exp,
					       const nfs_fh4 *fh,
					       const struct attrlist *attr)
{
	struct fs_obj_handle *n = gsh_calloc(1, sizeof(*n) + fh->nfs_fh4_len);

	if (n) {
		n->fh4 = *fh;
		n->fh4.nfs_fh4_val = n->blob.bytes;
		memcpy(n->blob.bytes, fh->nfs_fh4_val, fh->nfs_fh4_len);
		n->obj.attributes = *attr;
		n->blob.len = fh->nfs_fh4_len + sizeof(n->blob);
		n->blob.type = attr->type;
#ifdef PROXY_HANDLE_MAPPING
		int rc;
		memset(&n->h23, 0, sizeof(n->h23));
		n->h23.len = sizeof(n->h23);
		n->h23.type = PXY_HANDLE_MAPPED;
		n->h23.object_id = attr->fileid;
		n->h23.handle_hash = hash_nfs_fh4(fh, attr->fileid);

		rc = HandleMap_SetFH(&n->h23, &n->blob, n->blob.len);
		if ((rc != HANDLEMAP_SUCCESS) && (rc != HANDLEMAP_EXISTS)) {
			gsh_free(n);
			return NULL;
		}
#endif
		fsal_obj_handle_init(&n->obj, exp, attr->type);
	}
	return n;
}

/* export methods that create object handles
 */

fsal_status_t fs_lookup_path(struct fsal_export *exp_hdl,
			      const char *path,
			      struct fsal_obj_handle **handle)
{
	struct fsal_obj_handle *next;
	struct fsal_obj_handle *parent = NULL;
	char *saved;
	char *pcopy;
	char *p;
	struct user_cred *creds = op_ctx->creds;

	if (!path || path[0] != '/')
		return fsalstat(ERR_FSAL_INVAL, EINVAL);

	pcopy = gsh_strdup(path);
	if (!pcopy)
		return fsalstat(ERR_FSAL_NOMEM, ENOMEM);

	p = strtok_r(pcopy, "/", &saved);
	while (p) {
		if (strcmp(p, "..") == 0) {
			/* Don't allow lookup of ".." */
			LogInfo(COMPONENT_FSAL,
				"Attempt to use \"..\" element in path %s",
				path);
			gsh_free(pcopy);
			return fsalstat(ERR_FSAL_ACCESS, EACCES);
		}
		/* Note that if any element is a symlink, the following will
		 * fail, thus no security exposure.
		 */
		fsal_status_t st = fs_lookup_impl(parent, exp_hdl,
						   creds, p, &next);
		if (FSAL_IS_ERROR(st)) {
			gsh_free(pcopy);
			return st;
		}

		p = strtok_r(NULL, "/", &saved);
		parent = next;
	}
	/* The final element could be a symlink, but either way we are called
	 * will not work with a symlink, so no security exposure there.
	 */

	gsh_free(pcopy);
	*handle = next;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

fsal_status_t kernel_lookupplus(const char *path, struct fsal_obj_handle **handle)
{
	// struct fsal_obj_handle *parent = NULL;
	char *saved;
	char *pcopy;
	char *p;
	int rc;
	GETFH4resok *fhok;
	struct attrlist attributes = {0};
        struct fs_obj_handle *fs_hdl;
	int i = 0;
	int slash_cnt = 0;

	memset(&attributes, 0, sizeof(struct attrlist));
	if (!path || path[0] != '/')
		return fsalstat(ERR_FSAL_INVAL, EINVAL);

	while (path[i] != '\0') {
		if (path[i] == '/') {
			slash_cnt++;
		}
		i++;
	}

	pcopy = gsh_strdup(path);
	if (!pcopy)
		return fsalstat(ERR_FSAL_NOMEM, ENOMEM);

        tc_reset_compound(true);

	COMPOUNDV4_ARG_ADD_OP_PUTROOTFH(opcnt, argoparray);

	p = strtok_r(pcopy, "/", &saved);
	while (p) {
		if (strcmp(p, "..") == 0) {
			/* Don't allow lookup of ".." */
			LogInfo(COMPONENT_FSAL,
				"Attempt to use \"..\" element in path %s",
				path);
			gsh_free(pcopy);
			return fsalstat(ERR_FSAL_ACCESS, EACCES);
		}
		/* Note that if any element is a symlink, the following will
		 * fail, thus no security exposure.
		 */
		COMPOUNDV4_ARG_ADD_OP_LOOKUP(opcnt, argoparray, p);
		p = strtok_r(NULL, "/", &saved);
	}
	/* The final element could be a symlink, but either way we are called
	 * will not work with a symlink, so no security exposure there.
	 */

	fhok = &resoparray[opcnt].nfs_resop4_u.opgetfh.GETFH4res_u.resok4;
	COMPOUNDV4_ARG_ADD_OP_GETFH(opcnt, argoparray);

	gsh_free(pcopy);

	rc = fs_nfsv4_call(op_ctx->creds, NULL);
	if (rc != NFS4_OK)
		return nfsstat4_to_fsal(rc);

	fs_hdl =
	    fs_alloc_handle(op_ctx->fsal_export, &fhok->object, &attributes);
	if (fs_hdl == NULL) {
		return fsalstat(ERR_FSAL_FAULT, 0);
	}
	*handle = &fs_hdl->obj;

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/*
 * Create an FSAL 'object' from the handle - used
 * to construct objects from a handle which has been
 * 'extracted' by .extract_handle.
 */
fsal_status_t fs_create_handle(struct fsal_export *exp_hdl,
				struct gsh_buffdesc *hdl_desc,
				struct fsal_obj_handle **handle)
{
	fsal_status_t st;
	nfs_fh4 fh4;
	struct attrlist attr = {0};
	struct fs_obj_handle *ph;
	struct fs_handle_blob *blob;

	blob = (struct fs_handle_blob *)hdl_desc->addr;
	if (blob->len != hdl_desc->len)
		return fsalstat(ERR_FSAL_INVAL, 0);

	fh4.nfs_fh4_val = blob->bytes;
	fh4.nfs_fh4_len = blob->len - sizeof(*blob);

	st = fs_getattrs_impl(op_ctx->creds, exp_hdl, &fh4, &attr);
	if (FSAL_IS_ERROR(st))
		return st;

	ph = fs_alloc_handle(exp_hdl, &fh4, &attr);
	if (!ph)
		return fsalstat(ERR_FSAL_FAULT, 0);

	*handle = &ph->obj;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

fsal_status_t fs_get_dynamic_info(struct fsal_export *exp_hdl,
				   struct fsal_obj_handle *obj_hdl,
				   fsal_dynamicfsinfo_t *infop)
{
	int rc;
	GETATTR4resok *atok;
	char fattr_blob[48];	/* 6 values, 8 bytes each */
	struct fs_obj_handle *ph;

	ph = container_of(obj_hdl, struct fs_obj_handle, obj);

        tc_reset_compound(true);

	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);
	atok =
	    fs_fill_getattr_reply(resoparray + opcnt, fattr_blob,
				   sizeof(fattr_blob));
	COMPOUNDV4_ARG_ADD_OP_GETATTR(opcnt, argoparray, fs_bitmap_fsinfo);

	rc = fs_nfsv4_call(op_ctx->creds, NULL);
	if (rc != NFS4_OK)
		return nfsstat4_to_fsal(rc);

	if (nfs4_Fattr_To_fsinfo(infop, &atok->obj_attributes) != NFS4_OK)
		return fsalstat(ERR_FSAL_INVAL, 0);

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/* Convert of-the-wire digest into unique 'handle' which
 * can be used to identify the object */
fsal_status_t fs_extract_handle(struct fsal_export *exp_hdl,
				 fsal_digesttype_t in_type,
				 struct gsh_buffdesc *fh_desc)
{
	struct fs_handle_blob *fsblob;
	size_t fh_size;

	if (!fh_desc || !fh_desc->addr)
		return fsalstat(ERR_FSAL_FAULT, EINVAL);

	fsblob = (struct fs_handle_blob *)fh_desc->addr;
	fh_size = fsblob->len;
#ifdef PROXY_HANDLE_MAPPING
	if (in_type == FSAL_DIGEST_NFSV3)
		fh_size = sizeof(nfs23_map_handle_t);
#endif
	if (fh_desc->len != fh_size) {
		LogMajor(COMPONENT_FSAL,
			 "Size mismatch for handle.  should be %lu, got %lu",
			 fh_size, fh_desc->len);
		return fsalstat(ERR_FSAL_SERVERFAULT, 0);
	}
#ifdef PROXY_HANDLE_MAPPING
	if (in_type == FSAL_DIGEST_NFSV3) {
		nfs23_map_handle_t *h23 = (nfs23_map_handle_t *) fh_desc->addr;

		if (h23->type != PXY_HANDLE_MAPPED)
			return fsalstat(ERR_FSAL_STALE, ESTALE);

		/* As long as HandleMap_GetFH copies nfs23 handle into
		 * the key before lookup I can get away with using
		 * the same buffer for input and output */
		if (HandleMap_GetFH(h23, fh_desc) != HANDLEMAP_SUCCESS)
			return fsalstat(ERR_FSAL_STALE, 0);
		fh_size = fh_desc->len;
	}
#endif

	fh_desc->len = fh_size;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

