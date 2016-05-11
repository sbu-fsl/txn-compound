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
static sequenceid4 fs_sequenceid;
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
        if (masks->has_mode) {
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
				 const struct user_cred *creds, uint32_t cnt,
				 nfs_argop4 *argoparray, nfs_resop4 *resoparray,
				 nfsstat4 *nfsstat)
{
	enum clnt_stat rc;
	struct fs_rpc_io_context *ctx;
	COMPOUND4args arg = {
		.minorversion = 1,
		.argarray.argarray_val = argoparray,
		.argarray.argarray_len = cnt
	};
	COMPOUND4res res = {
		.resarray.resarray_val = resoparray,
		.resarray.resarray_len = cnt
	};

	pthread_mutex_lock(&context_lock);
	while (glist_empty(&free_contexts))
		pthread_cond_wait(&need_context, &context_lock);
	ctx =
	    glist_first_entry(&free_contexts, struct fs_rpc_io_context, calls);
	glist_del(&ctx->calls);
	pthread_mutex_unlock(&context_lock);

	do {
		rc = fs_compoundv4_call(ctx, creds, &arg, &res);
		if (rc != RPC_SUCCESS)
			NFS4_DEBUG("RPC by %s failed with %d", caller, rc);
		if (rc == RPC_CANTSEND)
			fs_rpc_need_sock();
	} while ((rc == RPC_CANTRECV && (ctx->ioresult == -EAGAIN))
		 || (rc == RPC_CANTSEND));

	pthread_mutex_lock(&context_lock);
	pthread_cond_signal(&need_context);
	glist_add(&free_contexts, &ctx->calls);
	pthread_mutex_unlock(&context_lock);

	if (rc == RPC_SUCCESS) {
               if (nfsstat != NULL) {
                        *nfsstat = res.status;
               } else {
                       rc = res.status;
               }
        }
	return rc;
}

#define fs_nfsv4_call(creds, cnt, args, resp, st) \
	fs_compoundv4_execute(__func__, creds, cnt, args, resp, st)

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
	int opcnt = 0;
#define FSAL_CLIENTID_NB_OP_ALLOC 2
	nfs_argop4 arg[FSAL_CLIENTID_NB_OP_ALLOC];
	nfs_resop4 res[FSAL_CLIENTID_NB_OP_ALLOC];
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

	sok = &res[0].nfs_resop4_u.opsetclientid.SETCLIENTID4res_u.resok4;
	arg[0].argop = NFS4_OP_SETCLIENTID;
	arg[0].nfs_argop4_u.opsetclientid.client = nfsclientid;
	arg[0].nfs_argop4_u.opsetclientid.callback = cbkern;
	arg[0].nfs_argop4_u.opsetclientid.callback_ident = 1;

	rc = fs_nfsv4_call(NULL, 1, arg, res, NULL);
	if (rc != NFS4_OK)
		return -1;

	arg[0].argop = NFS4_OP_SETCLIENTID_CONFIRM;
	arg[0].nfs_argop4_u.opsetclientid_confirm.clientid = sok->clientid;
	memcpy(arg[0].nfs_argop4_u.opsetclientid_confirm.setclientid_confirm,
	       sok->setclientid_confirm, NFS4_VERIFIER_SIZE);

	rc = fs_nfsv4_call(NULL, 1, arg, res, NULL);
	if (rc != NFS4_OK)
		return -1;

	/* Keep the confirmed client id */
	*resultclientid = arg[0].nfs_argop4_u.opsetclientid_confirm.clientid;

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

static int fs_sequence(nfs_argop4 *arg, nfs_resop4 *res)
{

	arg->argop = NFS4_OP_SEQUENCE;
        memcpy(&arg->nfs_argop4_u.opsequence.sa_sessionid, &fs_sessionid,
               NFS4_SESSIONID_SIZE);
        /* TODO: use atomic operation on fs_sequenceid */
        arg->nfs_argop4_u.opsequence.sa_sequenceid = fs_sequenceid++;
        arg->nfs_argop4_u.opsequence.sa_slotid = 0;
        arg->nfs_argop4_u.opsequence.sa_highest_slotid = 0;
        arg->nfs_argop4_u.opsequence.sa_cachethis = false;

        return 0;
}

static fsal_status_t fs_destroy_session()
{
        int rc;
        nfs_argop4 arg;
        nfs_resop4 res;

        arg.argop = NFS4_OP_DESTROY_SESSION;
        memcpy(&arg.nfs_argop4_u.opdestroy_session.dsa_sessionid,
               &fs_sessionid, NFS4_SESSIONID_SIZE);

        rc = fs_nfsv4_call(NULL, 1, &arg, &res, NULL);
        if (rc != NFS4_OK) {
		nfsstat4_to_fsal(rc);
	}

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static int fs_reclaim_complete()
{
        int rc;
#define FSAL_RECLAIM_COMPLETE_NB_OP_ALLOC 2
	nfs_argop4 arg[FSAL_RECLAIM_COMPLETE_NB_OP_ALLOC];
        nfs_resop4 res[FSAL_RECLAIM_COMPLETE_NB_OP_ALLOC];
	int opcnt = 0;

	fs_sequence(arg, res);
	opcnt++;

	arg[1].argop = NFS4_OP_RECLAIM_COMPLETE;
	arg[1].nfs_argop4_u.opreclaim_complete.rca_one_fs = false;
	opcnt++;

        rc = fs_nfsv4_call(NULL, opcnt, arg, res, NULL);
        if (rc != NFS4_OK) {
		return -1;
	}

	return 0;
}

static int fs_create_session()
{
	int rc;
	nfs_argop4 arg;
	nfs_resop4 res;
	char machname[MAXHOSTNAMELEN + 1];
	client_owner4 nfsclientowner;
	uint32_t eia_flags;
	channel_attrs4 csa_fore_chan_attrs = { .ca_headerpadsize = 0,
					       .ca_maxrequestsize = 1049620,
					       .ca_maxresponsesize = 1049480,
					       .ca_maxresponsesize_cached =
						   4616,
					       .ca_maxoperations = 64,
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
	uint32_t csa_flags;
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

	arg.argop = NFS4_OP_EXCHANGE_ID;
	eia = &arg.nfs_argop4_u.opexchange_id;
	eia->eia_clientowner = nfsclientowner;
	eia->eia_flags = eia_flags;
	eia->eia_state_protect.spa_how = SP4_NONE;
	eia->eia_client_impl_id.eia_client_impl_id_len = 0;

	eir = &res.nfs_resop4_u.opexchange_id.EXCHANGE_ID4res_u.eir_resok4;
	eir->eir_server_owner.so_major_id.so_major_id_val = server_major_id_buf;
	eir->eir_server_scope.eir_server_scope_val = server_scope_buf;
	eir->eir_server_impl_id.eir_server_impl_id_val = &server_impl_id;

	rc = fs_nfsv4_call(NULL, 1, &arg, &res, NULL);
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

	arg.argop = NFS4_OP_CREATE_SESSION;
	csa = &arg.nfs_argop4_u.opcreate_session;
	csa->csa_clientid = eir->eir_clientid;
	csa->csa_sequence = eir->eir_sequenceid;
	csa->csa_flags = 1;
	csa->csa_fore_chan_attrs = csa_fore_chan_attrs;
	csa->csa_back_chan_attrs = csa_back_chan_attrs;
	csa->csa_cb_program = 0x40000000;
	csa->csa_sec_parms.csa_sec_parms_val = &csa_sec_parms_val;
	csa->csa_sec_parms.csa_sec_parms_len = 1;

	LogEvent(COMPONENT_FSAL, "create session called");
	rc = fs_nfsv4_call(NULL, 1, &arg, &res, NULL);
	if (rc != NFS4_OK) {
		LogEvent(COMPONENT_FSAL, "create session failed: %d", rc);
		return -1;
	}

	csr = &res.nfs_resop4_u.opcreate_session.CREATE_SESSION4res_u.csr_resok4;
	memcpy(&fs_sessionid, csr->csr_sessionid, NFS4_SESSIONID_SIZE);
	fs_sequenceid = csr->csr_sequence;

	//fs_destroy_session();
	fs_reclaim_complete();

	return 0;
}

static void *fs_clientid_renewer(void *Arg)
{
	int rc;
	int needed = 1;
	nfs_argop4 arg;
	nfs_resop4 res;
	uint32_t lease_time = 60;

	while (1) {
		clientid4 newcid = 0;

		if (!needed && fs_rpc_renewer_wait(lease_time - 5)) {
			/* Simply renew the client id you've got */
			LogDebug(COMPONENT_FSAL, "Renewing client id %lx",
				 fs_clientid);
			arg.argop = NFS4_OP_RENEW;
			arg.nfs_argop4_u.oprenew.clientid = fs_clientid;
			rc = fs_nfsv4_call(NULL, 1, &arg, &res, NULL);
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

/* TODO: use thread-local variable and save all allocation */
#define MAX_NUM_OPS_PER_COMPOUND 128
/*static __thread nfs_argop4 argoparray[MAX_NUM_OPS_PER_COMPOUND];*/
/*static __thread nfs_resop4 resoparray[MAX_NUM_OPS_PER_COMPOUND];*/
/*static __thread int opcnt;*/
static __thread char tc_fhbuf[MAX_NUM_OPS_PER_COMPOUND * NFS4_FHSIZE];

struct nfsoparray {
        nfs_argop4 *argoparray;
        nfs_resop4 *resoparray;
        int opcnt;
        int capacity;
};

static struct nfsoparray *new_nfs_ops(int count)
{
        struct nfsoparray *nfsops = malloc(sizeof(*nfsops));
        if (!nfsops) {
                return NULL;
        }

        nfsops->argoparray = malloc(sizeof(nfs_argop4) * count);
        if (!nfsops->argoparray) {
                free(nfsops);
                return NULL;
        }

        nfsops->resoparray = malloc(sizeof(nfs_resop4) * count);
        if (!nfsops->resoparray) {
                free(nfsops->argoparray);
                free(nfsops);
                return NULL;
        }

        nfsops->opcnt = 0;
        nfsops->capacity = count;

        return nfsops;
}

static void del_nfs_ops(struct nfsoparray *nfsops)
{
        free(nfsops->resoparray);
        free(nfsops->argoparray);
        free(nfsops);
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
	uint32_t opcnt = 0;
	GETATTR4resok *atok;
	GETFH4resok *fhok;
#define FSAL_ROOTLOOKUP_NB_OP_ALLOC 3
	nfs_argop4 argoparray[FSAL_ROOTLOOKUP_NB_OP_ALLOC];
	nfs_resop4 resoparray[FSAL_ROOTLOOKUP_NB_OP_ALLOC];
	char fattr_blob[FATTR_BLOB_SZ];
	char padfilehandle[NFS4_FHSIZE];

	if (!handle)
		return fsalstat(ERR_FSAL_INVAL, 0);

	COMPOUNDV4_ARG_ADD_OP_PUTROOTFH(opcnt, argoparray);

	fhok = &resoparray[opcnt].nfs_resop4_u.opgetfh.GETFH4res_u.resok4;
	COMPOUNDV4_ARG_ADD_OP_GETFH(opcnt, argoparray);

	atok =
		fs_fill_getattr_reply(resoparray + opcnt, fattr_blob,
				sizeof(fattr_blob));

	COMPOUNDV4_ARG_ADD_OP_GETATTR(opcnt, argoparray, fs_bitmap_getattr);

	fhok->object.nfs_fh4_val = (char *)padfilehandle;
	fhok->object.nfs_fh4_len = sizeof(padfilehandle);

	rc = fs_nfsv4_call(cred, opcnt, argoparray, resoparray, NULL);
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
	uint32_t opcnt = 1;
	GETATTR4resok *atok;
	GETFH4resok *fhok;
#define FSAL_LOOKUP_NB_OP_ALLOC 5
	nfs_argop4 argoparray[FSAL_LOOKUP_NB_OP_ALLOC];
	nfs_resop4 resoparray[FSAL_LOOKUP_NB_OP_ALLOC];
	char fattr_blob[FATTR_BLOB_SZ];
	char padfilehandle[NFS4_FHSIZE];

	LogDebug(COMPONENT_FSAL, "lookup_impl() called\n");

	if (!handle)
		return fsalstat(ERR_FSAL_INVAL, 0);

	fs_sequence(argoparray, resoparray);

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

	rc = fs_nfsv4_call(cred, opcnt, argoparray, resoparray, NULL);
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
	int opcnt = 0;
#define FSAL_CLOSE_NB_OP_ALLOC 2
	nfs_argop4 argoparray[FSAL_CLOSE_NB_OP_ALLOC];
	nfs_resop4 resoparray[FSAL_CLOSE_NB_OP_ALLOC];
	char All_Zero[] = "\0\0\0\0\0\0\0\0\0\0\0\0";	/* 12 times \0 */

	/* Check if this was a "stateless" open,
	 * then nothing is to be done at close */
	if (!memcmp(sid->other, All_Zero, 12))
		return fsalstat(ERR_FSAL_NO_ERROR, 0);

	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, *fh4);
	COMPOUNDV4_ARG_ADD_OP_CLOSE(opcnt, argoparray, sid);

	rc = fs_nfsv4_call(creds, opcnt, argoparray, resoparray, NULL);
	if (rc != NFS4_OK)
		return nfsstat4_to_fsal(rc);
	sid->seqid++;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/*
 * Similar to fs_do_close, only difference being this accepts seqid
 * This is because for operations which involve modifying the state,
 * seqid for a lock owner keeps changing.
 * So caller has to make sure it passes the right seqid from kfd structure
 */
static fsal_status_t tc_do_close(const struct user_cred *creds,
				 const nfs_fh4 *fh4, stateid4 *sid,
				 seqid4 *seqid, struct fsal_export *exp)
{
	int rc;
	int opcnt = 0;
#define FSAL_TCCLOSE_NB_OP_ALLOC 3
	nfs_argop4 argoparray[FSAL_TCCLOSE_NB_OP_ALLOC];
	nfs_resop4 resoparray[FSAL_TCCLOSE_NB_OP_ALLOC];
	char All_Zero[] = "\0\0\0\0\0\0\0\0\0\0\0\0";	/* 12 times \0 */

	/* Check if this was a "stateless" open,
	 * then nothing is to be done at close */
	if (!memcmp(sid->other, All_Zero, 12))
		return fsalstat(ERR_FSAL_NO_ERROR, 0);

	fs_sequence(argoparray, resoparray);
	opcnt++;

	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, *fh4);
	COMPOUNDV4_ARG_ADD_OP_TCCLOSE(opcnt, argoparray, *seqid, (*sid));

	rc = fs_nfsv4_call(creds, opcnt, argoparray, resoparray, NULL);
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

static inline void tc_prepare_sequence(struct nfsoparray *nfsops)
{
        /* SEQUENCE should be the first operation of a compound. */
        assert(nfsops->opcnt == 0);
        fs_sequence(nfsops->argoparray, nfsops->resoparray);
        nfsops->opcnt = 1;
}

static inline OPEN_CONFIRM4resok *
tc_prepare_open_confirm(struct nfsoparray *nfsops, stateid4 *stateid)
{
	OPEN_CONFIRM4args *ocargs;
	OPEN_CONFIRM4resok *ocok;
	int n = nfsops->opcnt;

	ocargs = &nfsops->argoparray[n].nfs_argop4_u.opopen_confirm;
	ocok = &nfsops->resoparray[n]
		    .nfs_resop4_u.opopen_confirm.OPEN_CONFIRM4res_u.resok4;

	nfsops->argoparray[n].argop = NFS4_OP_OPEN_CONFIRM;
	copy_stateid4(&ocargs->open_stateid, stateid);
	ocargs->seqid = 1;
	nfsops->opcnt = n + 1;

	return ocok;
}

static fsal_status_t fs_open_confirm(const struct user_cred *cred,
				      const nfs_fh4 *fh4, stateid4 *stateid,
				      struct fsal_export *export)
{
	int rc;
	int opcnt = 0;
#define FSAL_PROXY_OPEN_CONFIRM_NB_OP_ALLOC 3
	nfs_argop4 argoparray[FSAL_PROXY_OPEN_CONFIRM_NB_OP_ALLOC];
	nfs_resop4 resoparray[FSAL_PROXY_OPEN_CONFIRM_NB_OP_ALLOC];
	nfs_argop4 *op;
	OPEN_CONFIRM4resok *conok;

	fs_sequence(argoparray, resoparray);
	opcnt++;

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

	rc = fs_nfsv4_call(cred, opcnt, argoparray, resoparray, NULL);
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
	int opcnt = 0;
	fattr4 input_attr;
	char padfilehandle[NFS4_FHSIZE];
	char fattr_blob[FATTR_BLOB_SZ];
#define FSAL_CREATE_NB_OP_ALLOC 4
	nfs_argop4 argoparray[FSAL_CREATE_NB_OP_ALLOC];
	nfs_resop4 resoparray[FSAL_CREATE_NB_OP_ALLOC];
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

	ph = container_of(dir_hdl, struct fs_obj_handle, obj);
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);

	opok = &resoparray[opcnt].nfs_resop4_u.opopen.OPEN4res_u.resok4;
	opok->attrset = empty_bitmap;
	fs_get_clientid(&cid);
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

	rc = fs_nfsv4_call(op_ctx->creds, opcnt, argoparray, resoparray, NULL);
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
	int opcnt = 0;
	/*struct fs_obj_handle *ph;*/
#define FSAL_READSTATE_NB_OP_ALLOC 6
	nfs_argop4 argoparray[FSAL_READSTATE_NB_OP_ALLOC];
	nfs_resop4 resoparray[FSAL_READSTATE_NB_OP_ALLOC];
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

	rc = fs_nfsv4_call(op_ctx->creds, opcnt, argoparray, resoparray, NULL);
	if (rc != NFS4_OK)
		return nfsstat4_to_fsal(rc);

	*end_of_file = rok->eof;
	*read_amount = rok->data.data_len;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/*
 * Parse path, start from putrootfh and send multiple lookups till we get
 * to the last directory.
 * Lookup is not sent for the file becase open is send with the filename
 * Marker variable is updated to the location of the "filename" in path
 *
 * Returns -1 in the case of invalid paths, 0 otherwise
 */
static int construct_lookup(char *path, nfs_argop4 *argoparray, int *opcnt_temp,
			    int *marker)
{
        int opcnt = *opcnt_temp;
        char *saved;
        char *pcopy;
        char *p;
        char *temp;
        *marker = 1;

        pcopy = gsh_strdup(path);
        temp = malloc(MAX_FILENAME_LENGTH);
        if (temp == NULL) {
                goto error_after_gsh;
        }
        COMPOUNDV4_ARG_ADD_OP_PUTROOTFH(opcnt, argoparray);

        p = strtok_r(pcopy, "/", &saved);
        while (p) {
                if (strcmp(p, "..") == 0) {
                        /* Don't allow lookup of ".." */
                        LogInfo(COMPONENT_FSAL,
                                "Attempt to use \"..\" element in path %s",
                                path);
                        goto error_after_temp;
                }
                strncpy(temp, p, MAX_FILENAME_LENGTH);
                p = strtok_r(NULL, "/", &saved);
                if (p) {
                        COMPOUNDV4_ARG_ADD_OP_LOOKUPNAME(
                            opcnt, argoparray, (path + *marker), strlen(temp));
                        *marker += (strlen(temp) + 1);
                }
        }

        gsh_free(pcopy);
        free(temp);
        *opcnt_temp = opcnt;

        return 0;

error_after_temp:
        free(temp);
error_after_gsh:
        gsh_free(pcopy);
        return -1;
}

#define TC_BASE_PATH_CURRENT 1
#define TC_BASE_PATH_ROOT 2
#define TC_BASE_PATH_SAVED 3
#define TC_BASE_PATH_CWD 4

static int construct_lookups(slice_t *comps, int compcnt,
			     nfs_argop4 *argoparray, int *opcnt, int base)
{
        int i;
        int new_opcnt = *opcnt;
        nfs_fh4 cwdfh;
        struct tc_cwd_data *cwd;

        if (base == TC_BASE_PATH_ROOT) {
                COMPOUNDV4_ARG_ADD_OP_PUTROOTFH(new_opcnt, argoparray);
        } else if (base == TC_BASE_PATH_SAVED) {
                COMPOUNDV4_ARG_ADD_OP_RESTOREFH(new_opcnt, argoparray);
        } else if (base == TC_BASE_PATH_CWD) {
		cwd = tc_get_cwd();
                cwdfh.nfs_fh4_val = tc_fhbuf + new_opcnt * NFS4_FHSIZE;
                cwdfh.nfs_fh4_len = cwd->fh.nfs_fh4_len;
		memmove(cwdfh.nfs_fh4_val, cwd->fh.nfs_fh4_val,
			cwd->fh.nfs_fh4_len);
		COMPOUNDV4_ARG_ADD_OP_PUTFH(new_opcnt, argoparray, cwdfh);
                tc_put_cwd(cwd);
	} else {
		// Nothing need to be done if base is the current file handle
		assert(base == TC_BASE_PATH_CURRENT);
        }

        for (i = 0; i < compcnt; ++i) {
                if (comps[i].data[0] == '.' && comps[i].size == 1)
                        continue;
		if (strncmp(comps[i].data, "..", comps[i].size) == 0) {
			COMPOUNDV4_ARG_ADD_OP_LOOKUPP(new_opcnt, argoparray);
		} else {
			COMPOUNDV4_ARG_ADD_OP_LOOKUPNAME(new_opcnt, argoparray,
							 comps[i].data,
							 comps[i].size);
		}
	}

        i = new_opcnt - *opcnt;
        *opcnt = new_opcnt;
        return i;
}

static int tc_set_cfh_to_path(const char *path, nfs_argop4 *argoparray,
			      int *opcnt, slice_t *leaf, bool use_cfh)
{
	slice_t *comps = NULL; /* path components */
	int n;		       /* number of path compontents */
	int base;
	int old_opcnt = *opcnt;

        NFS4_DEBUG("Set current FH to %s", path);
	n = tc_path_tokenize(path, &comps);
	if (n < 0) {
		NFS4_ERR("Cannot tokenize path: %s", path);
		return -1;
	}
        if (path[0] == '/') {
                base = TC_BASE_PATH_ROOT;
                comps[0].data++;  // skip the leading '/'
                comps[0].size--;
        } else if (use_cfh) {
                base = TC_BASE_PATH_CURRENT;
        } else {
                base = TC_BASE_PATH_CWD;
        }
	if (leaf) {
		*leaf = comps[--n];
	}
        construct_lookups(comps, n, argoparray, opcnt, base);

	free(comps);
	return *opcnt - old_opcnt;
}

static int tc_set_cfh_to_handle(const struct file_handle *h,
				struct nfsoparray *nfsops)
{
	nfs_fh4 fh4;

	fh4.nfs_fh4_len = h->handle_bytes;
	fh4.nfs_fh4_val = (char *)h->f_handle;
	COMPOUNDV4_ARG_ADD_OP_PUTFH(nfsops->opcnt, nfsops->argoparray, fh4);

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
static int tc_set_current_fh(const tc_file *tcf, struct nfsoparray *nfsops,
			     slice_t *leaf)
{
        int rc;

	if (tcf->type == TC_FILE_PATH || tcf->type == TC_FILE_CURRENT) {
		rc = tc_set_cfh_to_path(tcf->path, nfsops->argoparray,
					&nfsops->opcnt, leaf,
					tcf->type == TC_FILE_CURRENT);
	} else if (tcf->type == TC_FILE_HANDLE) {
                rc = tc_set_cfh_to_handle(tcf->handle, nfsops);
	} else {
		NFS4_ERR("unsupported type: %d", tcf->type);
		rc = -1;
	}

	return rc;
}

static int tc_set_saved_fh(const tc_file *tcf, struct nfsoparray *nfsops,
			   slice_t *leaf)
{
        int rc;

        rc = tc_set_current_fh(tcf, nfsops, leaf);
        if (rc >= 0) {
		COMPOUNDV4_ARG_ADD_OP_SAVEFH(nfsops->opcnt, nfsops->argoparray);
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

/*
 * Called for each tcread element in the tcread_kargs array
 * Adds operations to argoparray, also updates the opcnt_temp
 */
static fsal_status_t do_ktcread(struct tcread_kargs *kern_arg,
				nfs_argop4 *argoparray, nfs_resop4 *resoparray,
				int *opcnt_temp,
				int *last_op, buf_t *owner_pbuf)
{
	int opcnt = *opcnt_temp;
        char *owner_val;
	unsigned int owner_len = 0;
	clientid4 cid;
        slice_t name;
        READ4resok *rok;

	LogDebug(COMPONENT_FSAL, "do_ktcread() called: %d\n", opcnt);

        tc_new_state_owner(owner_pbuf);
        owner_val = owner_pbuf->data;
        owner_len = owner_pbuf->size;

	kern_arg->user_arg->is_failure = 0;
	kern_arg->user_arg->is_eof = 0;

	switch (kern_arg->user_arg->file.type) {
	case TC_FILE_CURRENT:
		/*
		 * Current filehandle is assumed to be set,
		 * so just send read
		 */
		if (*last_op == TC_FILE_START) {
			/* path/fd for the first element should not be empty */
			return fsalstat(ERR_FSAL_INVAL, -1);
		}

		rok = &resoparray[opcnt].nfs_resop4_u.opread.READ4res_u.resok4;
		rok->data.data_val = kern_arg->user_arg->data;
		rok->data.data_len = kern_arg->user_arg->length;

		if (*last_op == TC_FILE_PATH) {
			COMPOUNDV4_ARG_ADD_OP_READ(opcnt, argoparray,
						   kern_arg->user_arg->offset,
						   kern_arg->user_arg->length);
		} else if (*last_op == TC_FILE_DESCRIPTOR) {
			COMPOUNDV4_ARG_ADD_OP_READ_STATE(
			    opcnt, argoparray, kern_arg->user_arg->offset,
			    kern_arg->user_arg->length, kern_arg->sid);
		}
		break;
	case TC_FILE_DESCRIPTOR:

		if (*last_op == TC_FILE_PATH) {
			COMPOUNDV4_ARG_ADD_OP_CLOSE_NOSTATE(opcnt, argoparray);
		}

		COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, *kern_arg->fh);

		rok = &resoparray[opcnt].nfs_resop4_u.opread.READ4res_u.resok4;
		rok->data.data_val = kern_arg->user_arg->data;
		rok->data.data_len = kern_arg->user_arg->length;
		COMPOUNDV4_ARG_ADD_OP_READ_STATE(
		    opcnt, argoparray, kern_arg->user_arg->offset,
		    kern_arg->user_arg->length, kern_arg->sid);

		*last_op = TC_FILE_DESCRIPTOR;
		break;
	case TC_FILE_PATH:
		/*
		 * File path is not empty, so
		 *  1) Close the already opened file
		 *  2) Parse the file-path,
		 *  3) Start from putrootfh and keeping adding lookups,
		 *  4) Followed by open and read
		 */

		if (*last_op == TC_FILE_PATH) {
			/*
			 * No need to send close if its the first read request
			 */
			COMPOUNDV4_ARG_ADD_OP_CLOSE_NOSTATE(opcnt, argoparray);
		}

		/*
		 * Parse the file-path and send lookups to set the current
		 * file-handle
		 */

		if (tc_set_cfh_to_path(kern_arg->path, argoparray, &opcnt,
				       &name, false) == -1) {
			goto exit_pathinval;
		}

		kern_arg->opok_handle =
		    &resoparray[opcnt].nfs_resop4_u.opopen.OPEN4res_u.resok4;

		kern_arg->opok_handle->attrset = empty_bitmap;
		tc_get_clientid(&cid);

		assert(!kern_arg->user_arg->is_creation);
		COMPOUNDV4_ARG_ADD_OP_OPEN_NOCREATE(
		    opcnt, argoparray, 0 /*seq id*/, cid, name, owner_val,
		    owner_len, OPEN4_SHARE_ACCESS_READ);

		rok = &resoparray[opcnt].nfs_resop4_u.opread.READ4res_u.resok4;
		rok->data.data_val = kern_arg->user_arg->data;
		rok->data.data_len = kern_arg->user_arg->length;
		COMPOUNDV4_ARG_ADD_OP_READ(opcnt, argoparray,
					   kern_arg->user_arg->offset,
					   kern_arg->user_arg->length);
		*last_op = TC_FILE_PATH;
		break;
	default:
		return fsalstat(ERR_FSAL_INVAL, -1);
		break;
	}

	*opcnt_temp = opcnt;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);

exit_pathinval:
	return fsalstat(ERR_FSAL_INVAL, 0);
}

/*
 * Send multiple reads for one or more files
 * kern_arg - an array of tcread args with size "arg_count"
 * fail_index - Returns the position (read) inside the array that failed
 *  (in case of failure)
 *  The failure could be in putrootfh, lookup, open, read or close,
 *  fail_index would only point to the read call because it is unaware
 *  of the putrootfh, lookup, open or close
 * Caller has to make sure kern_arg and fields inside are allocated
 * and freed
 */
static fsal_status_t ktcread(struct tcread_kargs *kern_arg, int arg_count,
			     int *fail_index)
{
	int rc;
	fsal_status_t st;
        nfsstat4 cpd_status;
	nfsstat4 op_status;
	struct tcread_kargs *cur_arg = NULL;
        const int NB_OP_ALLOC = ((MAX_DIR_DEPTH + 3) * arg_count);
	nfs_argop4 *argoparray = NULL;
	nfs_resop4 *resoparray = NULL;
	struct READ4resok *read_res;
	int opcnt = 0;
	int last_op = TC_FILE_START;
	int i = 0;      /* index of tc_iovec */
	int j = 0;      /* index of NFS operations */

	LogDebug(COMPONENT_FSAL, "ktcread() called\n");

	argoparray = malloc(NB_OP_ALLOC * sizeof(struct nfs_argop4));
	resoparray = malloc(NB_OP_ALLOC * sizeof(struct nfs_resop4));
        assert(argoparray);
        assert(resoparray);

	fs_sequence(argoparray, resoparray);
	opcnt++;

	while (i < arg_count) {
		cur_arg = kern_arg + i;

		NFS4_DEBUG("path: %s; offset: %d; len: %d; data: %p",
			   cur_arg->user_arg->file.path,
			   cur_arg->user_arg->offset, cur_arg->user_arg->length,
			   cur_arg->user_arg->data);

		st = do_ktcread(cur_arg, argoparray, resoparray, &opcnt,
				&last_op, new_auto_buf(64));

		if (FSAL_IS_ERROR(st)) {
                        NFS4_ERR("do_ktcread failed: major=%d, minor=%d\n",
                                 st.major, st.minor);
			goto exit;
		}

		i++;
	}

	if (last_op == TC_FILE_PATH) {
		COMPOUNDV4_ARG_ADD_OP_CLOSE_NOSTATE(opcnt, argoparray);
	}

	rc = fs_nfsv4_call(op_ctx->creds, opcnt, argoparray, resoparray,
			   &cpd_status);
	if (rc != RPC_SUCCESS) {    /* RPC failed */
                NFS4_ERR("fs_nfsv4_call() returned error: %d\n", rc);
                st = fsalstat(ERR_FSAL_SERVERFAULT, rc);
                goto exit;
        }

        /* No matter NFS failed or succeeded, we need to fill in results */
        i = 0;
        for (j = 0; j < opcnt; ++j) {
                op_status = get_nfs4_op_status(&resoparray[j]);
                if (op_status != NFS4_OK) {
                        *fail_index = i;
			kern_arg[i].user_arg->is_failure = 1;
			NFS4_ERR("the %d-th tc_iovec failed (NFS op: %d)", i,
				 resoparray[j].resop);
                        break;
                }
                if (resoparray[j].resop == NFS4_OP_READ) {
			read_res = &resoparray[j]
					.nfs_resop4_u.opread.READ4res_u.resok4;
			kern_arg[i].user_arg->length = read_res->data.data_len;
			kern_arg[i].user_arg->is_eof = read_res->eof;
                        i++;
		}
	}

        st = nfsstat4_to_fsal(cpd_status);

exit:
	free(argoparray);
	free(resoparray);
	return st;
}

/*
 * Called for each tcwrite element in the tcwrite_kargs array
 * Adds operations to argoparray, also updates the opcnt_temp
 */
static fsal_status_t do_ktcwrite(struct tcwrite_kargs *kern_arg,
				 nfs_argop4 *argoparray, nfs_resop4 *resoparray,
				 int *opcnt_temp, fattr4 *input_attr,
				 int *last_op, buf_t *owner_pbuf)
{
	int opcnt = *opcnt_temp;
        char *owner_val;
	unsigned int owner_len = 0;
	clientid4 cid;
        slice_t name;
        const stateid4 *sid;

	LogDebug(COMPONENT_FSAL, "do_ktcwrite() called: %d\n", opcnt);

	/* Create the owner */
        tc_new_state_owner(owner_pbuf);
        owner_val = owner_pbuf->data;
        owner_len = owner_pbuf->size;

	kern_arg->user_arg->is_failure = 0;
	kern_arg->user_arg->is_eof = 0;

	switch (kern_arg->user_arg->file.type) {
	case TC_FILE_CURRENT:
		/*
                 * Current filehandle is assumed to be set,
                 * so just send read
                 */
                if (*last_op == TC_FILE_START) {
                        /* path/fd for the first element should not be empty */
                        return fsalstat(ERR_FSAL_INVAL, -1);
                }

		if (*last_op == TC_FILE_PATH) {
                        sid = &CURSID;
		} else if (*last_op == TC_FILE_DESCRIPTOR) {
                        sid = kern_arg->sid;
		}
		COMPOUNDV4_ARG_ADD_OP_WRITE_STATE(
		    opcnt, argoparray, kern_arg->user_arg->offset,
		    kern_arg->user_arg->data, kern_arg->user_arg->length, sid);

		break;

	case TC_FILE_DESCRIPTOR:

                if (*last_op == TC_FILE_PATH) {
                        COMPOUNDV4_ARG_ADD_OP_CLOSE_NOSTATE(opcnt, argoparray);
                }

		COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, *kern_arg->fh);

		COMPOUNDV4_ARG_ADD_OP_WRITE_STATE(
		    opcnt, argoparray, kern_arg->user_arg->offset,
		    kern_arg->user_arg->data, kern_arg->user_arg->length,
		    kern_arg->sid);

		*last_op = TC_FILE_DESCRIPTOR;
                break;

	case TC_FILE_PATH:
                /*
                 * File path is not empty, so
                 *  1) Close the already opened file
                 *  2) Parse the file-path,
                 *  3) Start from putrootfh and keeping adding lookups,
                 *  4) Followed by open and read
                 */

                if (*last_op == TC_FILE_PATH) {
                        /*
                         * No need to send close if its the first read request
                         */
                        COMPOUNDV4_ARG_ADD_OP_CLOSE_NOSTATE(opcnt, argoparray);
                }

		/*
		 * Parse the file-path and send lookups to set the current
		 * file-handle
		 */
		if (tc_set_cfh_to_path(kern_arg->path, argoparray, &opcnt,
				       &name, false) == -1) {
			goto error_pathinval;
		}

		kern_arg->opok_handle =
		    &resoparray[opcnt].nfs_resop4_u.opopen.OPEN4res_u.resok4;

		kern_arg->opok_handle->attrset = empty_bitmap;
		tc_get_clientid(&cid);

		if (kern_arg->user_arg->is_creation) {
			kern_arg->attrib.mode = unix2fsal_mode((mode_t)0644);
			FSAL_SET_MASK(kern_arg->attrib.mask, ATTR_MODE);

			if (FSAL_TEST_MASK(kern_arg->attrib.mask, ATTR_MODE)) {
				kern_arg->attrib.mode &=
				    ~op_ctx->fsal_export->ops->fs_umask(
					op_ctx->fsal_export);
			}

			if (fs_fsalattr_to_fattr4(&kern_arg->attrib,
						  input_attr) == -1) {
				return fsalstat(ERR_FSAL_INVAL, -1);
			}

                        NFS4_DEBUG("writing to '%s'", new_auto_str(name));
			COMPOUNDV4_ARG_ADD_OP_TCOPEN_CREATE(
			    opcnt, argoparray, 0 /*seq id*/, cid, *input_attr,
                            name, owner_val, owner_len);
		} else {
			input_attr->attrmask = empty_bitmap;
                        NFS4_DEBUG("writing to '%s'", new_auto_str(name));
			COMPOUNDV4_ARG_ADD_OP_OPEN_NOCREATE(
			    opcnt, argoparray, 0 /*seq id*/, cid,
			    name, owner_val, owner_len,
                            OPEN4_SHARE_ACCESS_BOTH);
		}

		COMPOUNDV4_ARG_ADD_OP_WRITE_STATE(
		    opcnt, argoparray, kern_arg->user_arg->offset,
		    kern_arg->user_arg->data, kern_arg->user_arg->length,
                    (&CURSID));

		*last_op = TC_FILE_PATH;
                break;
        default:
                return fsalstat(ERR_FSAL_INVAL, -1);
                break;
	}

	*opcnt_temp = opcnt;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);

error_pathinval:
	return fsalstat(ERR_FSAL_INVAL, 0);
}

/*
 * Send multiple writes for one or more files
 * kern_arg - an array of tcread args with size "arg_count"
 * fail_index - Returns the position (read) inside the array that failed
 *  (in case of failure)
 *  The failure could be in putrootfh, lookup, open, read or close,
 *  fail_index would only point to the read call because it is unaware
 *  of the putrootfh, lookup, open or close
 * Caller has to make sure kern_arg and fields inside are allocated
 * and freed
 */
static fsal_status_t ktcwrite(struct tcwrite_kargs *kern_arg, int arg_count,
			      int *fail_index)
{
	int rc;
	fsal_status_t st;
	nfsstat4 op_status;
        nfsstat4 cpd_status;
	struct tcwrite_kargs *cur_arg = NULL;
        const int NB_OP_ALLOC = ((MAX_DIR_DEPTH + 3) * arg_count);
	nfs_argop4 *argoparray = NULL;
	nfs_resop4 *resoparray = NULL;
        struct WRITE4resok *write_res = NULL;
	fattr4 *input_attr = NULL;
	int opcnt = 0;
	int last_op = TC_FILE_START;
	int i = 0;      /* index of tc_iovec */
	int j = 0;      /* index of NFS operations */

	LogDebug(COMPONENT_FSAL, "ktcwrite() called\n");

	argoparray = malloc(NB_OP_ALLOC * sizeof(struct nfs_argop4));
	resoparray = malloc(NB_OP_ALLOC * sizeof(struct nfs_resop4));
        assert(argoparray);
        assert(resoparray);

	fs_sequence(argoparray, resoparray);
	opcnt++;

	input_attr = calloc(arg_count, sizeof(fattr4));

	while (i < arg_count) {
		cur_arg = kern_arg + i;
		st = do_ktcwrite(cur_arg, argoparray, resoparray, &opcnt,
				 &input_attr[i], &last_op, new_auto_buf(64));

		if (FSAL_IS_ERROR(st)) {
			NFS4_ERR("do_ktcwrite failed: major=%d, minor=%d\n",
				 st.major, st.minor);
			goto exit;
		}

		i++;
	}

	if (last_op == TC_FILE_PATH) {
		COMPOUNDV4_ARG_ADD_OP_CLOSE_NOSTATE(opcnt, argoparray);
	}

	rc = fs_nfsv4_call(op_ctx->creds, opcnt, argoparray, resoparray,
			   &cpd_status);
	if (rc != RPC_SUCCESS) {
		NFS4_ERR("fs_nfsv4_call() returned error: %d (%s)\n", rc,
			 strerror(rc));
                st = fsalstat(ERR_FSAL_SERVERFAULT, rc);
                goto exit;
	}

        /* No matter failure or success, we need to fill in results */
        i = 0;
        for (j = 0; j < opcnt; ++j) {
                op_status = get_nfs4_op_status(&resoparray[j]);
                if (op_status != NFS4_OK) {
                        *fail_index = i;
			kern_arg[i].user_arg->is_failure = 1;
			NFS4_ERR("the %d-th tc_iovec failed (NFS op: %d)", i,
				 resoparray[j].resop);
			break;
                }
                if (resoparray[j].resop == NFS4_OP_WRITE) {
			write_res =
			    &resoparray[j]
				 .nfs_resop4_u.opwrite.WRITE4res_u.resok4;
			kern_arg[i].user_arg->length = write_res->count;
			kern_arg[i].user_arg->is_write_stable =
			    (write_res->committed != UNSTABLE4);
			i++;
                }
        }

        st = nfsstat4_to_fsal(cpd_status);

exit:
	for (i = 0; i < arg_count; ++i) {
		nfs4_Fattr_Free(&input_attr[i]);
	}
	free(input_attr);
	free(argoparray);
	free(resoparray);
	return st;
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

static fsal_status_t do_ktcopen(struct tcopen_kargs *kern_arg, int flags,
                                nfs_argop4 *argoparray, nfs_resop4 *resoparray,
                                int *opcnt_temp, fattr4 *input_attr)
{
	int opcnt = *opcnt_temp;
	char owner_val[128];
	unsigned int owner_len = 0;
	clientid4 cid;
	uint32_t open_type = 0;
        slice_t name;

	LogDebug(COMPONENT_FSAL, "do_ktcopen() called: %d\n", opcnt);

        owner_len = tc_create_state_owner(owner_val);

	if (tc_set_cfh_to_path(kern_arg->path, argoparray, &opcnt, &name,
			       false) < 0) {
		goto exit_pathinval;
	}

	kern_arg->opok_handle =
	    &resoparray[opcnt].nfs_resop4_u.opopen.OPEN4res_u.resok4;

	kern_arg->opok_handle->attrset = empty_bitmap;
	tc_get_clientid(&cid);

	input_attr->attrmask = empty_bitmap;

        open_type = tc_open_flags_to_access(flags);

	if ((flags & O_CREAT) != 0) {
		kern_arg->attrib.mode = unix2fsal_mode((mode_t)0644);
		FSAL_SET_MASK(kern_arg->attrib.mask, ATTR_MODE);

		if (FSAL_TEST_MASK(kern_arg->attrib.mask, ATTR_MODE)) {
			kern_arg->attrib.mode &=
			    ~op_ctx->fsal_export->ops->fs_umask(
				op_ctx->fsal_export);
		}

		if (fs_fsalattr_to_fattr4(&kern_arg->attrib, input_attr) == -1)
			return fsalstat(ERR_FSAL_INVAL, -1);

		LogDebug(COMPONENT_FSAL, "do_ktcopen() Bitmap: "
					 "%d%d%d, len:%u\n",
			 input_attr->attrmask.map[0],
			 input_attr->attrmask.map[1],
			 input_attr->attrmask.map[2],
			 input_attr->attrmask.bitmap4_len);

		COMPOUNDV4_ARG_ADD_OP_TCOPEN_CREATE(opcnt, argoparray, 0, cid,
						    *input_attr, name,
						    owner_val, owner_len);
	} else {
		COMPOUNDV4_ARG_ADD_OP_OPEN_NOCREATE(opcnt, argoparray, 0, cid,
						    name, owner_val, owner_len,
						    open_type);
	}

	kern_arg->fhok_handle =
	    &resoparray[opcnt].nfs_resop4_u.opgetfh.GETFH4res_u.resok4;

	kern_arg->fhok_handle->object.nfs_fh4_val = malloc(NFS4_FHSIZE);
	kern_arg->fhok_handle->object.nfs_fh4_len = NFS4_FHSIZE;
	COMPOUNDV4_ARG_ADD_OP_GETFH(opcnt, argoparray);

	*opcnt_temp = opcnt;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);

exit_pathinval:
	return fsalstat(ERR_FSAL_INVAL, 0);
}

/*
 * tc version of open system call
 * Should be called only if new fd can be allocated
 * Caller has to make sure incr_seqid() is called if this succeeds
 *
 * flags currently supports O_RDONLY, O_WRONLY, O_RDWR and O_CREAT
 */
static fsal_status_t ktcopen(struct tcopen_kargs *kern_arg, int flags)
{
	int rc;
	fsal_status_t st;
#define FSAL_TCOPEN_NB_OP_ALLOC (MAX_DIR_DEPTH + 4)
	nfs_argop4 *argoparray = NULL;
	nfs_resop4 *resoparray = NULL;
	fattr4 *input_attr = NULL;
	int opcnt = 0;

	LogDebug(COMPONENT_FSAL, "ktcopen() called\n");

	argoparray =
	    malloc(FSAL_TCOPEN_NB_OP_ALLOC * sizeof(struct nfs_argop4));
	resoparray =
	    malloc(FSAL_TCOPEN_NB_OP_ALLOC * sizeof(struct nfs_resop4));

	fs_sequence(argoparray, resoparray);
	opcnt++;

	input_attr = malloc(sizeof(fattr4));
	memset(input_attr, 0, sizeof(fattr4));

	st = do_ktcopen(kern_arg, flags, argoparray, resoparray, &opcnt,
			input_attr);

	if (FSAL_IS_ERROR(st)) {
		NFS4_ERR("do_ktcopen failed: major=%d, minor=%d\n", st.major,
			 st.minor);
		goto exit;
	}

	rc = fs_nfsv4_call(op_ctx->creds, opcnt, argoparray, resoparray, NULL);

	st = fsalstat(ERR_FSAL_NO_ERROR, 0);

	if (rc != NFS4_OK) {
		NFS4_ERR("fs_nfsv4_call() returned error: %d\n", rc);
		st = nfsstat4_to_fsal(rc);
		goto exit;
	}

exit:
	free(input_attr);
	free(argoparray);
	free(resoparray);
	return st;
}

/*
 * Close an already opened file
 * Sets the current fh to fh4 and closes sid, seqid has to be passed from fd
 */
static fsal_status_t ktcclose(const nfs_fh4 *fh4, stateid4 *sid, seqid4 *seqid)
{
	fsal_status_t st;

	st = tc_do_close(op_ctx->creds, fh4, sid, seqid, op_ctx->fsal_export);

	return st;
}

static inline CREATE4resok *tc_prepare_mkdir(struct nfsoparray *nfsops,
					     const char *name, fattr4 *fattr)
{
        CREATE4resok *crok;
        int n = nfsops->opcnt;

        NFS4_DEBUG("op (%d) of compound: mkdir(\"%s\")", n, name);
	crok = &nfsops->resoparray[n].nfs_resop4_u.opcreate.CREATE4res_u.resok4;
	crok->attrset = empty_bitmap;
	COMPOUNDV4_ARG_ADD_OP_MKDIR(n, nfsops->argoparray, (char *)name, *fattr);
	nfsops->opcnt = n;

        return crok;
}

static inline void tc_prepare_putfh(struct nfsoparray *nfsops, nfs_fh4 *fh)
{
	COMPOUNDV4_ARG_ADD_OP_PUTFH(nfsops->opcnt, nfsops->argoparray, *fh);
}

/**
 * Set up the GETATTR operation.
 */
static inline GETATTR4resok *tc_prepare_getattr(struct nfsoparray *nfsops,
						char *fattr_blob)
{
	GETATTR4resok *atok;
        int n = nfsops->opcnt;

	atok = fs_fill_getattr_reply(nfsops->resoparray + n, fattr_blob,
				     FATTR_BLOB_SZ);
	COMPOUNDV4_ARG_ADD_OP_GETATTR(n, nfsops->argoparray, fs_bitmap_getattr);
	nfsops->opcnt = n;

        return atok;
}

/**
 * Set up the SETATTR operation.
 */
static inline SETATTR4res *tc_prepare_setattr(struct nfsoparray *nfsops,
					      const fattr4 *fattr)
{
        SETATTR4res *res;
        int n = nfsops->opcnt;

	res = &nfsops->resoparray[n].nfs_resop4_u.opsetattr;
	nfsops->resoparray[n].nfs_resop4_u.opsetattr.attrsset = empty_bitmap;
	COMPOUNDV4_ARG_ADD_OP_SETATTR(n, nfsops->argoparray, *fattr);
        nfsops->opcnt = n;

        return res;
}

/**
 * Set up the GETFH operation.
 */
static inline GETFH4resok *tc_prepare_getfh(struct nfsoparray *nfsops, char *fh)
{
	GETFH4resok *fhok;
        int n = nfsops->opcnt;

	fhok = &nfsops->resoparray[n].nfs_resop4_u.opgetfh.GETFH4res_u.resok4;
	fhok->object.nfs_fh4_val = fh;
	fhok->object.nfs_fh4_len = NFS4_FHSIZE;
	COMPOUNDV4_ARG_ADD_OP_GETFH(n, nfsops->argoparray);
	nfsops->opcnt = n;

        return fhok;
}

/**
 * @owner_pbuf: pbuf for owner
 * @attrs: initial attributes for file creation.
 */
static inline OPEN4resok *tc_prepare_open(struct nfsoparray *nfsops,
					  slice_t name, int flags,
                                          buf_t *owner_pbuf, fattr4 *attrs)
{
	OPEN4resok *opok;
	int n = nfsops->opcnt;
	clientid4 cid;
	OPEN4args *args;

	tc_new_state_owner(owner_pbuf);
	fs_get_clientid(&cid);

	nfsops->argoparray[n].argop = NFS4_OP_OPEN;
	args = &nfsops->argoparray[n].nfs_argop4_u.opopen;
	args->seqid = 0;
	args->share_access = tc_open_flags_to_access(flags);
	args->share_deny = OPEN4_SHARE_DENY_NONE;

	args->owner.clientid = cid;
	args->owner.owner.owner_val = owner_pbuf->data;
	args->owner.owner.owner_len = owner_pbuf->size;

	if (attrs) {
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

	opok = &nfsops->resoparray[n].nfs_resop4_u.opopen.OPEN4res_u.resok4;
	nfsops->opcnt = n + 1;

	return opok;
}

/* The caller should release "rdok->reply.entries" */
static inline READDIR4resok *tc_prepare_readdir(struct nfsoparray *nfsops,
						nfs_cookie4 *cookie,
						int dircount,
						const struct bitmap4 *attrbm)
{
        READDIR4resok *rdok;
        int n = nfsops->opcnt;

	rdok =
	    &nfsops->resoparray[n].nfs_resop4_u.opreaddir.READDIR4res_u.resok4;
	rdok->reply.entries = NULL;
	COMPOUNDV4_ARG_ADD_OP_READDIR(n, nfsops->argoparray, *cookie, dircount,
				      (attrbm ? fs_bitmap_readdir : *attrbm));
	nfsops->opcnt = n;

	return rdok;
}

static inline REMOVE4resok *tc_prepare_remove(struct nfsoparray *nfsops,
                                              char *name)
{
        REMOVE4resok *rmok;

	rmok = &nfsops->resoparray[nfsops->opcnt]
		    .nfs_resop4_u.opremove.REMOVE4res_u.resok4;
	COMPOUNDV4_ARG_ADD_OP_REMOVE(nfsops->opcnt, nfsops->argoparray, name);

        return rmok;
}

static inline COPY4res *tc_prepare_copy(struct nfsoparray *nfsops,
					size_t src_offset, size_t dst_offset,
					size_t count)
{
	COPY4res *cpres;

	cpres = &nfsops->resoparray[nfsops->opcnt].nfs_resop4_u.opcopy;
	COMPOUNDV4_ARG_ADD_OP_COPY(nfsops->opcnt, nfsops->argoparray,
				   src_offset, dst_offset, count);

	return cpres;
}

static inline utf8string slice2ustr(const slice_t *sl) {
        utf8string ustr = {
                .utf8string_val = (char *)sl->data,
                .utf8string_len = sl->size,
        };
        return ustr;
}

static inline RENAME4resok *tc_prepare_rename(struct nfsoparray *nfsops,
                                              const slice_t *srcname,
                                              const slice_t *dstname)
{
	RENAME4resok *rnok;
	nfs_argop4 *op;

        op = nfsops->argoparray + nfsops->opcnt;
	rnok = &nfsops->resoparray[nfsops->opcnt]
		    .nfs_resop4_u.oprename.RENAME4res_u.resok4;
	op->argop = NFS4_OP_RENAME;
	op->nfs_argop4_u.oprename.oldname = slice2ustr(srcname);
	op->nfs_argop4_u.oprename.newname = slice2ustr(dstname);
        nfsops->opcnt++;

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
	int opcnt = 0;
	fattr4 input_attr;
	char padfilehandle[NFS4_FHSIZE];
	struct fs_obj_handle *ph;
	char fattr_blob[FATTR_BLOB_SZ];
	GETATTR4resok *atok;
	GETFH4resok *fhok;
	fsal_status_t st;
        struct nfsoparray *nfsops;

#define FSAL_MKDIR_NB_OP_ALLOC 4
        nfsops = new_nfs_ops(FSAL_MKDIR_NB_OP_ALLOC);

	/*
	 * The caller gives us partial attributes which include mode and owner
	 * and expects the full attributes back at the end of the call.
	 */
	attrib->mask &= ATTR_MODE | ATTR_OWNER | ATTR_GROUP;
	if (fs_fsalattr_to_fattr4(attrib, &input_attr) == -1)
		return fsalstat(ERR_FSAL_INVAL, -1);

	ph = container_of(dir_hdl, struct fs_obj_handle, obj);
        tc_prepare_putfh(nfsops, &ph->fh4);

        tc_prepare_mkdir(nfsops, name, &input_attr);

	fhok = tc_prepare_getfh(nfsops, padfilehandle);

	atok = tc_prepare_getattr(nfsops, fattr_blob);

	rc = fs_nfsv4_call(op_ctx->creds, nfsops->opcnt, nfsops->argoparray,
			   nfsops->resoparray, NULL);
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
        del_nfs_ops(nfsops);
	return st;
}

static fsal_status_t fs_mknod(struct fsal_obj_handle *dir_hdl,
			       const char *name, object_file_type_t nodetype,
			       fsal_dev_t *dev, struct attrlist *attrib,
			       struct fsal_obj_handle **handle)
{
	int rc;
	int opcnt = 0;
	fattr4 input_attr;
	char padfilehandle[NFS4_FHSIZE];
	struct fs_obj_handle *ph;
	char fattr_blob[FATTR_BLOB_SZ];
	GETATTR4resok *atok;
	GETFH4resok *fhok;
	fsal_status_t st;
	enum nfs_ftype4 nf4type;
	specdata4 specdata = { 0, 0 };

	nfs_argop4 argoparray[4];
	nfs_resop4 resoparray[4];

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

	rc = fs_nfsv4_call(op_ctx->creds, opcnt, argoparray, resoparray, NULL);
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

static fsal_status_t fs_symlink(struct fsal_obj_handle *dir_hdl,
				 const char *name, const char *link_path,
				 struct attrlist *attrib,
				 struct fsal_obj_handle **handle)
{
	int rc;
	int opcnt = 0;
	fattr4 input_attr;
	char padfilehandle[NFS4_FHSIZE];
	char fattr_blob[FATTR_BLOB_SZ];
#define FSAL_SYMLINK_NB_OP_ALLOC 4
	nfs_argop4 argoparray[FSAL_SYMLINK_NB_OP_ALLOC];
	nfs_resop4 resoparray[FSAL_SYMLINK_NB_OP_ALLOC];
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

	ph = container_of(dir_hdl, struct fs_obj_handle, obj);
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);

	resoparray[opcnt].nfs_resop4_u.opcreate.CREATE4res_u.resok4.attrset =
	    empty_bitmap;
	COMPOUNDV4_ARG_ADD_OP_SYMLINK(opcnt, argoparray, (char *)name,
				      (char *)link_path, input_attr);

	fhok = &resoparray[opcnt].nfs_resop4_u.opgetfh.GETFH4res_u.resok4;
	fhok->object.nfs_fh4_val = padfilehandle;
	fhok->object.nfs_fh4_len = sizeof(padfilehandle);
	COMPOUNDV4_ARG_ADD_OP_GETFH(opcnt, argoparray);

	atok =
	    fs_fill_getattr_reply(resoparray + opcnt, fattr_blob,
				   sizeof(fattr_blob));
	COMPOUNDV4_ARG_ADD_OP_GETATTR(opcnt, argoparray, fs_bitmap_getattr);

	rc = fs_nfsv4_call(op_ctx->creds, opcnt, argoparray, resoparray, NULL);
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

static fsal_status_t fs_readlink(struct fsal_obj_handle *obj_hdl,
				  struct gsh_buffdesc *link_content,
				  bool refresh)
{
	int rc;
	int opcnt = 0;
	struct fs_obj_handle *ph;
#define FSAL_READLINK_NB_OP_ALLOC 2
	nfs_argop4 argoparray[FSAL_READLINK_NB_OP_ALLOC];
	nfs_resop4 resoparray[FSAL_READLINK_NB_OP_ALLOC];
	READLINK4resok *rlok;

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

	rlok = &resoparray[opcnt].nfs_resop4_u.opreadlink.READLINK4res_u.resok4;
	rlok->link.utf8string_val = link_content->addr;
	rlok->link.utf8string_len = link_content->len;
	COMPOUNDV4_ARG_ADD_OP_READLINK(opcnt, argoparray);

	rc = fs_nfsv4_call(op_ctx->creds, opcnt, argoparray, resoparray, NULL);
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
#define FSAL_LINK_NB_OP_ALLOC 4
	nfs_argop4 argoparray[FSAL_LINK_NB_OP_ALLOC];
	nfs_resop4 resoparray[FSAL_LINK_NB_OP_ALLOC];
	int opcnt = 0;

	/* Tests if hardlinking is allowed by configuration. */
	if (!op_ctx->fsal_export->ops->fs_supports(op_ctx->fsal_export,
						  fso_link_support))
		return fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);

	tgt = container_of(obj_hdl, struct fs_obj_handle, obj);
	dst = container_of(destdir_hdl, struct fs_obj_handle, obj);

	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, tgt->fh4);
	COMPOUNDV4_ARG_ADD_OP_SAVEFH(opcnt, argoparray);
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, dst->fh4);
	COMPOUNDV4_ARG_ADD_OP_LINK(opcnt, argoparray, (char *)name);

	rc = fs_nfsv4_call(op_ctx->creds, opcnt, argoparray, resoparray, NULL);
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
	uint32_t opcnt = 0;
	int rc;
	entry4 *e4;
#define FSAL_READDIR_NB_OP_ALLOC 2
	nfs_argop4 argoparray[FSAL_READDIR_NB_OP_ALLOC];
	nfs_resop4 resoparray[FSAL_READDIR_NB_OP_ALLOC];
	READDIR4resok *rdok;
	fsal_status_t st = { ERR_FSAL_NO_ERROR, 0 };
        const int dircount = 2048;

	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);
	rdok = &resoparray[opcnt].nfs_resop4_u.opreaddir.READDIR4res_u.resok4;
	rdok->reply.entries = NULL;
	COMPOUNDV4_ARG_ADD_OP_READDIR(opcnt, argoparray, *cookie, dircount,
				      fs_bitmap_readdir);

	rc = fs_nfsv4_call(op_ctx->creds, opcnt, argoparray, resoparray, NULL);
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
	int opcnt = 0;
#define FSAL_RENAME_NB_OP_ALLOC 4
	nfs_argop4 argoparray[FSAL_RENAME_NB_OP_ALLOC];
	nfs_resop4 resoparray[FSAL_RENAME_NB_OP_ALLOC];
	struct fs_obj_handle *src;
	struct fs_obj_handle *tgt;

	src = container_of(olddir_hdl, struct fs_obj_handle, obj);
	tgt = container_of(newdir_hdl, struct fs_obj_handle, obj);
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, src->fh4);
	COMPOUNDV4_ARG_ADD_OP_SAVEFH(opcnt, argoparray);
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, tgt->fh4);
	COMPOUNDV4_ARG_ADD_OP_RENAME(opcnt, argoparray, (char *)old_name,
				     (char *)new_name);

	rc = fs_nfsv4_call(op_ctx->creds, opcnt, argoparray, resoparray, NULL);
	return nfsstat4_to_fsal(rc);
}

static fsal_status_t fs_getattrs_impl(const struct user_cred *creds,
				       struct fsal_export *exp,
				       nfs_fh4 *filehandle,
				       struct attrlist *obj_attr)
{
	int rc;
	uint32_t opcnt = 0;
#define FSAL_GETATTR_NB_OP_ALLOC 2
	nfs_argop4 argoparray[FSAL_GETATTR_NB_OP_ALLOC];
	nfs_resop4 resoparray[FSAL_GETATTR_NB_OP_ALLOC];
	GETATTR4resok *atok;
	char fattr_blob[FATTR_BLOB_SZ];

	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, *filehandle);

	atok = fs_fill_getattr_reply(resoparray + opcnt, fattr_blob,
				      sizeof(fattr_blob));
	COMPOUNDV4_ARG_ADD_OP_GETATTR(opcnt, argoparray, fs_bitmap_getattr);

	rc = fs_nfsv4_call(creds, opcnt, argoparray, resoparray, NULL);
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
	uint32_t opcnt = 0;
	struct fs_obj_handle *ph;
	char fattr_blob[FATTR_BLOB_SZ];
	GETATTR4resok *atok;
	struct attrlist attrs_after = {0};

#define FSAL_SETATTR_NB_OP_ALLOC 3
	nfs_argop4 argoparray[FSAL_SETATTR_NB_OP_ALLOC];
	nfs_resop4 resoparray[FSAL_SETATTR_NB_OP_ALLOC];

	if (FSAL_TEST_MASK(attrs->mask, ATTR_MODE))
		attrs->mode &= ~op_ctx->fsal_export->ops->
				fs_umask(op_ctx->fsal_export);

	ph = container_of(obj_hdl, struct fs_obj_handle, obj);

	if (fs_fsalattr_to_fattr4(attrs, &input_attr) == -1)
		return fsalstat(ERR_FSAL_INVAL, EINVAL);

	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);

	resoparray[opcnt].nfs_resop4_u.opsetattr.attrsset = empty_bitmap;
	COMPOUNDV4_ARG_ADD_OP_SETATTR(opcnt, argoparray, input_attr);

	atok =
	    fs_fill_getattr_reply(resoparray + opcnt, fattr_blob,
				   sizeof(fattr_blob));
	COMPOUNDV4_ARG_ADD_OP_GETATTR(opcnt, argoparray, fs_bitmap_getattr);

	rc = fs_nfsv4_call(op_ctx->creds, opcnt, argoparray, resoparray, NULL);
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
	int opcnt = 0;
	int rc;
	struct fs_obj_handle *ph;
#define FSAL_UNLINK_NB_OP_ALLOC 3
	nfs_argop4 argoparray[FSAL_UNLINK_NB_OP_ALLOC];
	nfs_resop4 resoparray[FSAL_UNLINK_NB_OP_ALLOC];
	GETATTR4resok *atok;
	char fattr_blob[FATTR_BLOB_SZ];
	struct attrlist dirattr = {0};

	ph = container_of(dir_hdl, struct fs_obj_handle, obj);
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);
	COMPOUNDV4_ARG_ADD_OP_REMOVE(opcnt, argoparray, (char *)name);

	atok =
	    fs_fill_getattr_reply(resoparray + opcnt, fattr_blob,
				   sizeof(fattr_blob));
	COMPOUNDV4_ARG_ADD_OP_GETATTR(opcnt, argoparray, fs_bitmap_getattr);

	rc = fs_nfsv4_call(op_ctx->creds, opcnt, argoparray, resoparray, NULL);
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
	int opcnt = 0;
	struct fs_obj_handle *ph;
#define FSAL_READ_NB_OP_ALLOC 2
	nfs_argop4 argoparray[FSAL_READ_NB_OP_ALLOC];
	nfs_resop4 resoparray[FSAL_READ_NB_OP_ALLOC];
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

	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);
	rok = &resoparray[opcnt].nfs_resop4_u.opread.READ4res_u.resok4;
	rok->data.data_val = buffer;
	rok->data.data_len = buffer_size;
	COMPOUNDV4_ARG_ADD_OP_READ(opcnt, argoparray, offset, buffer_size);

	rc = fs_nfsv4_call(op_ctx->creds, opcnt, argoparray, resoparray, NULL);
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
	int opcnt = 0;
#define FSAL_WRITE_NB_OP_ALLOC 2
	nfs_argop4 argoparray[FSAL_WRITE_NB_OP_ALLOC];
	nfs_resop4 resoparray[FSAL_WRITE_NB_OP_ALLOC];
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
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);
	wok = &resoparray[opcnt].nfs_resop4_u.opwrite.WRITE4res_u.resok4;
	COMPOUNDV4_ARG_ADD_OP_WRITE(opcnt, argoparray, offset, buffer, size);

	rc = fs_nfsv4_call(op_ctx->creds, opcnt, argoparray, resoparray, NULL);
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
        int opcnt = 0;
        struct fs_obj_handle *ph;
#define FSAL_READ_PLUS_NB_OP_ALLOC 2
        nfs_argop4 argoparray[FSAL_READ_PLUS_NB_OP_ALLOC];
        nfs_resop4 resoparray[FSAL_READ_PLUS_NB_OP_ALLOC];
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

        COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);
        rp4res = &resoparray[opcnt].nfs_resop4_u.opread_plus;
        rpr4 = &rp4res->rpr_resok4;
        rpr4->rpr_contents_len = 1;
        rpr4->rpr_contents_val = &info->io_content;
        COMPOUNDV4_ARG_ADD_OP_READ_PLUS(opcnt, argoparray, offset,
                                        buffer_size, info->io_content.what);

	rc = fs_nfsv4_call(op_ctx->creds, opcnt, argoparray, resoparray, NULL);
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
	int opcnt = 0;
#define FSAL_WRITE_PLUS_NB_OP_ALLOC 2
	nfs_argop4 argoparray[FSAL_WRITE_PLUS_NB_OP_ALLOC];
	nfs_resop4 resoparray[FSAL_WRITE_PLUS_NB_OP_ALLOC];
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
	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);

        wp4res = &resoparray[opcnt].nfs_resop4_u.opwrite_plus;
        wpr4 = &wp4res->WRITE_PLUS4res_u.wpr_resok4;
        COMPOUNDV4_ARG_ADD_OP_WRITE_PLUS(opcnt, argoparray, (&info->io_content));

	rc = fs_nfsv4_call(op_ctx->creds, opcnt, argoparray, resoparray, NULL);
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
                attrlist.mode = tca->mode;
        }
        if (tca->masks.has_size) {
                attrlist.mask |= ATTR_SIZE;
                attrlist.filesize = tca->size;
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

        set_mode_type(&tca->mode, attrlist.type);
}

static tc_res tc_nfs4_openv(struct tc_attrs *attrs, int count, int *flags,
			    stateid4 *sids)
{
	int rc;
	tc_res tcres;
	nfsstat4 cpd_status;
	nfsstat4 op_status;
	struct nfsoparray *nfsops;
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
	nfsops = new_nfs_ops((MAX_DIR_DEPTH + 3) * count);
	assert(nfsops);
	fattrs = alloca(count * sizeof(fattr4));
	memset(fattrs, 0, count * sizeof(fattr4));
	fattr_blobs = (char *)alloca(count * FATTR_BLOB_SZ);
	fh_buffers = alloca(count * NFS4_FHSIZE); /* on stack */

        tc_prepare_sequence(nfsops);
	for (i = 0; i < count; ++i) {
		rc = tc_set_current_fh(&attrs[i].file, nfsops, &name);
		if (rc < 0) {
                        tcres = tc_failure(i, ERR_FSAL_INVAL);
                        goto exit;
                }
		tc_attrs_to_fattr4(&attrs[i], &fattrs[i]);
		tc_prepare_open(nfsops, name, flags[i], new_auto_buf(64),
				&fattrs[i]);
		tc_prepare_getfh(nfsops, fh_buffers + i * NFS4_FHSIZE);
		tc_prepare_getattr(nfsops, fattr_blobs + i * FATTR_BLOB_SZ);
	}

	rc = fs_nfsv4_call(op_ctx->creds, nfsops->opcnt, nfsops->argoparray,
			   nfsops->resoparray, &cpd_status);
        if (rc != RPC_SUCCESS) {
                NFS4_ERR("rpc failed: %d", rc);
                tcres = tc_failure(0, rc);
                goto exit;
        }

        i = 0;
        for (j = 0; j < nfsops->opcnt; ++j) {
                op_status = get_nfs4_op_status(nfsops->resoparray + j);
                if (op_status != NFS4_OK) {
                        NFS4_ERR("NFS operation (%d) failed: %d",
                                 nfsops->resoparray[j].resop, op_status);
                        tcres = tc_failure(i, nfsstat4_to_errno(op_status));
                        goto exit;
                }
                switch(nfsops->resoparray[j].resop) {
                case NFS4_OP_OPEN:
			opok = &nfsops->resoparray[j]
				    .nfs_resop4_u.opopen.OPEN4res_u.resok4;
			flags[i] = opok->rflags;
                        copy_stateid4(&sids[i], &opok->stateid);
			break;
                case NFS4_OP_GETFH:
			tc_file_set_handle(&attrs[i].file,
					   &nfsops->resoparray[j]
						.nfs_resop4_u.opgetfh
						.GETFH4res_u.resok4.object);
			break;
                case NFS4_OP_GETATTR:
			fattr4_to_tc_attrs(
			    &nfsops->resoparray[j]
				 .nfs_resop4_u.opgetattr.GETATTR4res_u.resok4
				 .obj_attributes,
			    attrs + i);
                        ++i;
			break;
                }
        }

	if (cpd_status == NFS4_OK)
		tcres.okay = true;

exit:
        for (i = 0; i < count; ++i) {
                nfs4_Fattr_Free(&fattrs[i]);
        }
        del_nfs_ops(nfsops);
        return tcres;
}

static tc_res tc_nfs4_closev(const nfs_fh4 *fh4s, int count, stateid4 *sids,
			     seqid4 *seqs)
{
        int i;
	int rc;
	tc_res tcres = {.okay = true };
	struct nfsoparray *nfsops;
	const static char All_Zero[] = "\0\0\0\0\0\0\0\0\0\0\0\0"; /* 12 0s */

	NFS4_DEBUG("tc_nfs4_closev");
	assert(count >= 1);
	nfsops = new_nfs_ops((MAX_DIR_DEPTH + 3) * count);
	assert(nfsops);

        tc_prepare_sequence(nfsops);
	for (i = 0; i < count; ++i) {
		// ignore stateless open
                if (memcmp(sids[i].other, All_Zero, 12)) {
			COMPOUNDV4_ARG_ADD_OP_PUTFH(
			    nfsops->opcnt, nfsops->argoparray, fh4s[i]);
			COMPOUNDV4_ARG_ADD_OP_TCCLOSE(nfsops->opcnt,
						      nfsops->argoparray,
						      seqs[i], sids[i]);
		}
        }

	rc = fs_nfsv4_call(op_ctx->creds, nfsops->opcnt, nfsops->argoparray,
			   nfsops->resoparray, NULL);
	if (rc != NFS4_OK) {
                NFS4_ERR("rpc failed: %d", rc);
                tcres = tc_failure(0, rc);
                goto exit;
        }

        for (i = 0; i < count; ++i) {
                sids[i].seqid++;
        }

exit:
        del_nfs_ops(nfsops);
        return tcres;
}

static tc_res tc_nfs4_getattrsv(struct tc_attrs *attrs, int count)
{
        int rc;
        tc_res tcres;
        nfsstat4 cpd_status;
	nfsstat4 op_status;
        struct nfsoparray *nfsops;
	GETATTR4resok *atok;
	int i = 0;      /* index of tc_iovec */
	int j = 0;      /* index of NFS operations */
	char *fattr_blobs; /* an array of FATTR_BLOB_SZ-sized buffers */

        NFS4_DEBUG("tc_nfs4_getattrsv");
        assert(count >= 1);
        nfsops = new_nfs_ops((MAX_DIR_DEPTH + 3) * count);
        assert(nfsops);
        fattr_blobs = (char *)malloc(count * FATTR_BLOB_SZ);
        assert(fattr_blobs);

        tc_prepare_sequence(nfsops);
        for (i = 0; i < count; ++i) {
		rc = tc_set_current_fh(&attrs[i].file, nfsops, NULL);
		if (rc < 0) {
                        tcres = tc_failure(i, ERR_FSAL_INVAL);
                        goto exit;
                }
		tc_prepare_getattr(nfsops, fattr_blobs + i * FATTR_BLOB_SZ);
	}

	rc = fs_nfsv4_call(op_ctx->creds, nfsops->opcnt, nfsops->argoparray,
			   nfsops->resoparray, &cpd_status);
	if (rc != RPC_SUCCESS) {
                NFS4_ERR("rpc failed: %d", rc);
                tcres = tc_failure(0, rc);
                goto exit;
        }

        i = 0;
	for (j = 0; j < nfsops->opcnt; ++j) {
                op_status = get_nfs4_op_status(&nfsops->resoparray[j]);
                if (op_status != NFS4_OK) {
			NFS4_ERR("NFS operation (%d) failed: %d",
				 nfsops->resoparray[j].resop, op_status);
			tcres = tc_failure(i, nfsstat4_to_errno(op_status));
                        goto exit;
                }
                if (nfsops->resoparray[j].resop != NFS4_OP_GETATTR)
                        continue;
		atok = &nfsops->resoparray[j]
			    .nfs_resop4_u.opgetattr.GETATTR4res_u.resok4;
		fattr4_to_tc_attrs(&atok->obj_attributes, attrs + i);
		++i;
	}
        tcres.okay = true;

exit:
        del_nfs_ops(nfsops);
        free(fattr_blobs);
        return tcres;
}

static tc_res tc_nfs4_setattrsv(struct tc_attrs *attrs, int count)
{
        int rc;
        tc_res tcres;
        nfsstat4 cpd_status;
	nfsstat4 op_status;
        struct nfsoparray *nfsops;
	fattr4 *new_fattrs;
	int i = 0;      /* index of tc_iovec */
	int j = 0;      /* index of NFS operations */
        fattr4 *fattrs; /* input attrs to set */
	char *fattr_blobs; /* an array of FATTR_BLOB_SZ-sized buffers */

        NFS4_DEBUG("tc_nfs4_setattrsv");
        nfsops = new_nfs_ops((MAX_DIR_DEPTH + 3) * count);
        assert(nfsops);
	fattrs = alloca(count * sizeof(fattr4));           /* on stack */
        fattr_blobs = alloca(count * FATTR_BLOB_SZ);

        tc_prepare_sequence(nfsops);
        for (i = 0; i < count; ++i) {
                tc_attrs_to_fattr4(&attrs[i], &fattrs[i]);
                rc = tc_set_current_fh(&attrs[i].file, nfsops, NULL);
                if (rc < 0) {
                        tcres = tc_failure(i, ERR_FSAL_INVAL);
                        goto exit;
                }
                tc_prepare_setattr(nfsops, &fattrs[i]);
                tc_prepare_getattr(nfsops, fattr_blobs + i * FATTR_BLOB_SZ);
        }

	rc = fs_nfsv4_call(op_ctx->creds, nfsops->opcnt, nfsops->argoparray,
			   nfsops->resoparray, &cpd_status);
        if (rc != RPC_SUCCESS) {
                NFS4_ERR("rpc failed: %d", rc);
                tcres = tc_failure(0, rc);
                goto exit;
        }

        i = 0;
        for (j = 0; j < nfsops->opcnt; ++j) {
                op_status = get_nfs4_op_status(&nfsops->resoparray[j]);
                if (op_status != NFS4_OK) {
			NFS4_ERR("NFS operation (%d) failed: %d",
				 nfsops->resoparray[j].resop, op_status);
			tcres = tc_failure(i, nfsstat4_to_errno(op_status));
                        goto exit;
                }
                switch (nfsops->resoparray[j].resop) {
                case NFS4_OP_SETATTR:
                        NFS4_DEBUG("SETATTR at %d succeeded", j);
                        break;
                case NFS4_OP_GETATTR:
			new_fattrs = &nfsops->resoparray[j]
					  .nfs_resop4_u.opgetattr.GETATTR4res_u
					  .resok4.obj_attributes;
			fattr4_to_tc_attrs(new_fattrs, attrs + i);
                        ++i;
                        break;
                }
        }

        tcres.okay = true;

exit:
        for (i = 0; i < count; ++i) {
                nfs4_Fattr_Free(fattrs + i);
        }
        del_nfs_ops(nfsops);
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
        nfsstat4 cpd_status;
        nfsstat4 op_status;
        struct nfsoparray *nfsops;
        char *fh_buffers;
        fattr4 *input_attrs;
        char *fattr_blobs;
	GETATTR4resok *atok;
        slice_t name;

        /* allocate space */
        NFS4_DEBUG("making %d directories", count);
        assert(count >= 1);
        nfsops = new_nfs_ops((MAX_DIR_DEPTH + 3) * count);
        assert(nfsops);
	input_attrs = alloca(count * sizeof(fattr4));   /* on stack */
        memset(input_attrs, 0, count * sizeof(fattr4));
	fattr_blobs = alloca(count * FATTR_BLOB_SZ);    /* on stack */
        fh_buffers = alloca(count * NFS4_FHSIZE);       /* on stack */

        tc_prepare_sequence(nfsops);
        /* prepare compound requests */
        for (i = 0; i < count; ++i) {
                tc_attrs_to_fattr4(&dirs[i], &input_attrs[i]);
		rc = tc_set_current_fh(&dirs[i].file, nfsops, &name);
		if (rc < 0) {
                        tcres = tc_failure(i, ERR_FSAL_INVAL);
                        goto exit;
                }

		tc_prepare_mkdir(nfsops, name.data, &input_attrs[i]);

		tc_prepare_getfh(nfsops, fh_buffers + i * NFS4_FHSIZE);

		tc_prepare_getattr(nfsops, fattr_blobs + i * FATTR_BLOB_SZ);
	}

	rc = fs_nfsv4_call(op_ctx->creds, nfsops->opcnt, nfsops->argoparray,
			   nfsops->resoparray, &cpd_status);
        if (rc != RPC_SUCCESS) {
                NFS4_ERR("rpc failed: %d", rc);
                tcres = tc_failure(0, rc);
                goto exit;
        }

        i = 0;
        for (j = 0; j < nfsops->opcnt; ++j) {
                op_status = get_nfs4_op_status(nfsops->resoparray + j);
                if (op_status != NFS4_OK) {
                        NFS4_ERR("NFS operation (%d) failed: %d",
                                 nfsops->resoparray[j].resop, op_status);
                        tcres = tc_failure(i, nfsstat4_to_errno(op_status));
                        goto exit;
                }
                switch(nfsops->resoparray[j].resop) {
                case NFS4_OP_CREATE:
                        ++i;
                        break;
                case NFS4_OP_GETFH:
			tc_file_set_handle(&dirs[i - 1].file,
					   &nfsops->resoparray[j]
						.nfs_resop4_u.opgetfh
						.GETFH4res_u.resok4.object);
			break;
                case NFS4_OP_GETATTR:
			atok =
			    &nfsops->resoparray[j]
				 .nfs_resop4_u.opgetattr.GETATTR4res_u.resok4;
			fattr4_to_tc_attrs(&atok->obj_attributes, dirs + i - 1);
                        break;
                }
        }

	if (cpd_status == NFS4_OK)
		tcres.okay = true;

exit:
        for (i = 0; i < count; ++i) {
                nfs4_Fattr_Free(input_attrs + i);
        }
        del_nfs_ops(nfsops);
        return tcres;
}

/**
 * Directory entries read by listdirv.
 */
struct tc_dir_entry_listed {
	struct glist_head siblings; /* entires share the same parent */
	struct tc_attrs attrs;
};

/**
 * A directory to be listed.
 */
struct tc_dir_to_list {
	struct glist_head list; /* list of all directories to be listed */
	const char *name;
        nfs_cookie4 cookie;
        char fhbuf[NFS4_FHSIZE];
        nfs_fh4 fh;
        int index;
        int nchildren;
        struct glist_head children;
        bool eof;
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

static int tc_parse_dir_entries(const entry4 *entries,
				struct glist_head *entrylist,
				nfs_cookie4 *cookie)
{
        struct tc_dir_entry_listed *dentry;
        int n = 0;
        while (entries) {
                dentry = calloc(1, sizeof(*dentry));
		dentry->attrs.file =
		    tc_file_from_path(strndup(entries->name.utf8string_val,
					      entries->name.utf8string_len));
		fattr4_to_tc_attrs(&entries->attrs, &dentry->attrs);
                *cookie = entries->cookie;
                glist_add_tail(entrylist, &dentry->siblings);
                entries = entries->nextentry;
                ++n;
        }
        return n;
}

static tc_res tc_do_listdirv(struct glist_head *dirlist, const bitmap4 *bitmap,
			     int max_entries_per_dir)
{
        struct tc_dir_to_list *dle;
        tc_file tcf;
        struct nfsoparray *nfsops;
        tc_res tcres;
        nfsstat4 cpd_status;
        nfsstat4 op_status;
        READDIR4resok *rdok;
        int count;
        int i, j;
        int rc;

        count = glist_length(dirlist);
        nfsops = new_nfs_ops((MAX_DIR_DEPTH + 3) * count);

        tc_prepare_sequence(nfsops);
        glist_for_each_entry(dle, dirlist, list) {
                if (dle->fh.nfs_fh4_len == 0) {
                        tcf = tc_file_from_path(dle->name);
                        tc_set_current_fh(&tcf, nfsops, NULL);
                        tc_prepare_getfh(nfsops, dle->fhbuf);
                } else {
                        tc_prepare_putfh(nfsops, &dle->fh);
		}
		tc_prepare_readdir(nfsops, &dle->cookie, max_entries_per_dir,
				   bitmap);
	}

	rc = fs_nfsv4_call(op_ctx->creds, nfsops->opcnt, nfsops->argoparray,
			   nfsops->resoparray, &cpd_status);
        if (rc != RPC_SUCCESS) {
                NFS4_ERR("rpc failed: %d", rc);
                tcres = tc_failure(0, rc);
                goto exit;
        }

        dle = glist_first_entry(dirlist, struct tc_dir_to_list, list);
        i = 0;
        for (j = 0; j < nfsops->opcnt; ++j) {
                op_status = get_nfs4_op_status(nfsops->resoparray + j);
                if (op_status != NFS4_OK) {
                        NFS4_ERR("NFS operation (%d) failed: %d",
                                 nfsops->resoparray[j].resop, op_status);
                        tcres = tc_failure(i, nfsstat4_to_errno(op_status));
                        goto exit;
                }
                switch(nfsops->resoparray[j].resop) {
                case NFS4_OP_GETFH:
			dle->fh =
			    nfsops->resoparray[j]
				.nfs_resop4_u.opgetfh.GETFH4res_u.resok4.object;
                        break;
                case NFS4_OP_READDIR:
			rdok =
			    &nfsops->resoparray[j]
				 .nfs_resop4_u.opreaddir.READDIR4res_u.resok4;
                        dle->eof = rdok->reply.eof;
			dle->nchildren += tc_parse_dir_entries(
			    rdok->reply.entries, &dle->children, &dle->cookie);
			++i;
                        dle = glist_next_entry(dle, list);
                        break;
		}
        }

        if (cpd_status == NFS4_OK)
                tcres.okay = true;

exit:
        xdr_free((xdrproc_t) xdr_listdirv, nfsops);
        del_nfs_ops(nfsops);
        return tcres;
}

tc_res tc_nfs4_listdirv(const char **dirs, int count,
			struct tc_attrs_masks masks, int max_entries,
			tc_listdirv_cb cb, void *cbarg)
{
        int i = 0;
        int ndir;
        int entries_per_dir;
        tc_res tcres;
        struct tc_attrs *entries;
	/**
	 * When max_entries is set, we only need the first "max_entries"
	 * entries.  However, because we read from all directories in parallel,
	 * we might read more than needed because we don't know how many
	 * entries are there in each directory.
	 */
	int entrycnt = 0; /* the number of entries read and needed */
	int entryread; /* the number of netries read but not necessary needed */
	GLIST_HEAD(dirlist);
        struct tc_dir_to_list *alldirs;
        struct tc_dir_to_list *dle;
        struct tc_dir_to_list *dle_next;
        struct tc_dir_entry_listed *dentry;
        struct tc_dir_entry_listed *dentry_next;
        bitmap4 bitmap = fs_bitmap_readdir;

        tc_attr_masks_to_bitmap(&masks, &bitmap);

        alldirs = alloca(count * sizeof(*alldirs));
        entries = alloca(sizeof(*entries) * MAX_ENTRIES_PER_COMPOUND);
        for (i = 0; i < count; ++i) {
                dle = alldirs + i;
                dle->name = dirs[i];
                dle->cookie = 0;
                dle->nchildren = 0;
                dle->index = i;
                dle->eof = false;
                dle->fh.nfs_fh4_len = 0;
                glist_init(&dle->children);
                glist_add_tail(&dirlist, &dle->list);
        }

        while (!glist_empty(&dirlist)) {
                entrycnt = 0;
                i = 0;
                do {
                        entrycnt += alldirs[i].nchildren;
                } while (alldirs[i++].eof);

                ndir = glist_length(&dirlist);
		entries_per_dir = MIN(max_entries - entrycnt,
				      MAX_ENTRIES_PER_COMPOUND / ndir);
		tcres = tc_do_listdirv(&dirlist, &bitmap, entries_per_dir);
		if (!tcres.okay) {
                        goto exit;
                }

                // find directories that still need to be listed
                // 1. Remove directories that are finished.
                glist_for_each_entry_safe(dle, dle_next, &dirlist, list) {
                        if (dle->eof) {
                                glist_del(&dle->list);
                        }
                }

		// 2. Remove directories that should not be read because of
		// max_entries.
                if (max_entries == 0) continue;
		entryread = 0;
                for (i = 0; i < count && entryread < max_entries; ++i) {
                        entryread += alldirs[i].nchildren;
                }
                for (; i < count; ++i) {
                        // Remove from the list; no-op if not in the list;
                        glist_del(&alldirs[i].list);
                }
	}

        for (i = 0; i < count; ++i) {
                dle = &alldirs[i];
		if (!glist_empty(&dle->children)) {
			glist_for_each_entry(dentry, &dle->children, siblings)
			{
				if (!cb(&dentry->attrs, dle->name, cbarg)) {
					goto exit;
				}
			}
		}
                if (!dle->eof) {
                        break;
                }
        }

exit:
        for (i = 0; i < count; ++i) {
                if (glist_empty(&alldirs[i].children)) {
                        continue;
                }
		glist_for_each_entry_safe(dentry, dentry_next,
					  &alldirs[i].children, siblings) {
                        if (!tcres.okay && dentry->attrs.file.path) {
                                free((void *)dentry->attrs.file.path);
                        }
                        glist_del(&dentry->siblings);
                        free(dentry);
		}
        }
        return tcres;
}

static tc_res tc_nfs4_renamev(tc_file_pair *pairs, int count)
{
        int rc;
        tc_res tcres;
        nfsstat4 cpd_status;
	nfsstat4 op_status;
        struct nfsoparray *nfsops;
	int i = 0;      /* index of tc_iovec */
	int j = 0;      /* index of NFS operations */
        slice_t srcname;
        slice_t dstname;

        NFS4_DEBUG("tc_nfs4_renamev");
        nfsops = new_nfs_ops((MAX_DIR_DEPTH + 3) * count);
        assert(nfsops);

        tc_prepare_sequence(nfsops);
        for (i = 0; i < count; ++i) {
                rc = tc_set_saved_fh(&pairs[i].src_file, nfsops, &srcname);
                if (rc < 0) {
                        tcres = tc_failure(i, ERR_FSAL_INVAL);
                        goto exit;
                }
                rc = tc_set_current_fh(&pairs[i].dst_file, nfsops, &dstname);
                if (rc < 0) {
                        tcres = tc_failure(i, ERR_FSAL_INVAL);
                        goto exit;
                }
                tc_prepare_rename(nfsops, &srcname, &dstname);
        }

        rc = fs_nfsv4_call(op_ctx->creds, nfsops->opcnt, nfsops->argoparray,
                           nfsops->resoparray, &cpd_status);
        if (rc != RPC_SUCCESS) {
                NFS4_ERR("rpc failed: %d", rc);
                tcres = tc_failure(0, rc);
                goto exit;
        }

        i = 0;
        for (j = 0; j < nfsops->opcnt; ++j) {
                op_status = get_nfs4_op_status(&nfsops->resoparray[j]);
                if (op_status != NFS4_OK) {
			NFS4_ERR("NFS operation (%d) failed: %d",
				 nfsops->resoparray[j].resop, op_status);
			tcres = tc_failure(i, nfsstat4_to_errno(op_status));
                        goto exit;
                }
                if (nfsops->resoparray[j].resop == NFS4_OP_RENAME) {
                        ++i;
                }
        }

        tcres.okay = true;

exit:
        del_nfs_ops(nfsops);
        return tcres;
}

static tc_res tc_nfs4_removev(tc_file *files, int count)
{
        int rc;
        tc_res tcres;
        nfsstat4 cpd_status;
	nfsstat4 op_status;
        struct nfsoparray *nfsops;
	int i = 0;      /* index of tc_iovec */
	int j = 0;      /* index of NFS operations */
        slice_t name;

        NFS4_DEBUG("tc_nfs4_removev");
        nfsops = new_nfs_ops((MAX_DIR_DEPTH + 3) * count);
        assert(nfsops);

        tc_prepare_sequence(nfsops);
        for (i = 0; i < count; ++i) {
                rc = tc_set_current_fh(&files[i], nfsops, &name);
                if (rc < 0) {
                        tcres = tc_failure(i, ERR_FSAL_INVAL);
                        goto exit;
                }
                tc_prepare_remove(nfsops, new_auto_str(name));
        }

	rc = fs_nfsv4_call(op_ctx->creds, nfsops->opcnt, nfsops->argoparray,
			   nfsops->resoparray, &cpd_status);
	if (rc != RPC_SUCCESS) {
                NFS4_ERR("rpc failed: %d", rc);
                tcres = tc_failure(0, rc);
                goto exit;
        }

        i = 0;
        for (j = 0; j < nfsops->opcnt; ++j) {
                op_status = get_nfs4_op_status(&nfsops->resoparray[j]);
                if (op_status != NFS4_OK) {
			NFS4_ERR("NFS operation (%d) failed: %d",
				 nfsops->resoparray[j].resop, op_status);
			tcres = tc_failure(i, nfsstat4_to_errno(op_status));
                        goto exit;
                }
                if (nfsops->resoparray[j].resop == NFS4_OP_REMOVE) {
                        ++i;
                }
        }

        tcres.okay = true;

exit:
        del_nfs_ops(nfsops);
        return tcres;
}

static tc_res tc_nfs4_copyv(struct tc_extent_pair *pairs, int count)
{
	int rc;
	tc_res tcres;
	nfsstat4 cpd_status;
	nfsstat4 op_status;
	struct nfsoparray *nfsops;
	int i = 0; /* index of tc_iovec */
	int j = 0; /* index of NFS operations */
	tc_file tcf;
	slice_t srcname;
	slice_t dstname;
        struct tc_attrs tca;
        fattr4 *attrs4;

	NFS4_DEBUG("tc_nfs4_removev");
	nfsops = new_nfs_ops((MAX_DIR_DEPTH + 3) * count);
	assert(nfsops);
        attrs4 = calloc(count, sizeof(*attrs4));
        assert(attrs4);

        tc_prepare_sequence(nfsops);
	for (i = 0; i < count; ++i) {
		tc_set_cfh_to_path(pairs[i].src_path, nfsops->argoparray,
				   &nfsops->opcnt, &srcname, false);
		tc_prepare_open(nfsops, srcname, O_RDONLY, new_auto_buf(64),
				NULL);
		COMPOUNDV4_ARG_ADD_OP_SAVEFH(nfsops->opcnt, nfsops->argoparray);

		tc_set_cfh_to_path(pairs[i].dst_path, nfsops->argoparray,
				   &nfsops->opcnt, &dstname, false);
                tc_set_up_creation(&tca, new_auto_str(dstname), 0755);
		tc_attrs_to_fattr4(&tca, &attrs4[i]);
		tc_prepare_open(nfsops, dstname, O_WRONLY | O_CREAT,
				new_auto_buf(64), &attrs4[i]);

		tc_prepare_copy(nfsops, pairs[i].src_offset,
				pairs[i].dst_offset, pairs[i].length);

		COMPOUNDV4_ARG_ADD_OP_CLOSE_NOSTATE(nfsops->opcnt,
						    nfsops->argoparray);
		COMPOUNDV4_ARG_ADD_OP_RESTOREFH(nfsops->opcnt,
						nfsops->argoparray);
		COMPOUNDV4_ARG_ADD_OP_CLOSE_NOSTATE(nfsops->opcnt,
						    nfsops->argoparray);
	}

	rc = fs_nfsv4_call(op_ctx->creds, nfsops->opcnt, nfsops->argoparray,
			   nfsops->resoparray, &cpd_status);
	if (rc != RPC_SUCCESS) {
                NFS4_ERR("rpc failed: %d", rc);
                tcres = tc_failure(0, rc);
                goto exit;
        }

	i = 0;
	for (j = 0; j < nfsops->opcnt; ++j) {
		op_status = get_nfs4_op_status(&nfsops->resoparray[j]);
		if (op_status != NFS4_OK) {
			NFS4_ERR("NFS operation (%d) failed: %d",
				 nfsops->resoparray[j].resop, op_status);
			tcres = tc_failure(i, nfsstat4_to_errno(op_status));
			goto exit;
		}
		if (nfsops->resoparray[j].resop == NFS4_OP_COPY) {
			pairs[i].length =
			    nfsops->resoparray[j]
				.nfs_resop4_u.opcopy.COPY4res_u.cr_bytes_copied;
			++i;
		}
	}

	tcres.okay = true;

exit:
	for (i = 0; i < count; ++i) {
		nfs4_Fattr_Free(&attrs4[i]);
	}
	free(attrs4);
	del_nfs_ops(nfsops);
	return tcres;
}

static int tc_nfs4_chdir(const char *path)
{
	int rc;
	struct nfsoparray *nfsops;
	struct tc_cwd_data *cwd;
	GETFH4resok *fhok;

	NFS4_DEBUG("tc_nfs4_chdir");
	nfsops = new_nfs_ops(MAX_DIR_DEPTH + 2);
	assert(nfsops);

	cwd = malloc(sizeof(*cwd));
	if (!cwd) {
		del_nfs_ops(nfsops);
		return -ENOMEM;
	}
	cwd->refcount = 1; // grap a refcount
	memmove(cwd->path, path, strlen(path));

        tc_prepare_sequence(nfsops);

	rc = tc_set_cfh_to_path(path, nfsops->argoparray, &nfsops->opcnt, NULL,
				false);
	fhok = tc_prepare_getfh(nfsops, cwd->fhbuf);

	rc = fs_nfsv4_call(op_ctx->creds, nfsops->opcnt, nfsops->argoparray,
			   nfsops->resoparray, NULL);
	if (rc != RPC_SUCCESS) {
		NFS4_ERR("rpc failed: %d", rc);
		free(cwd);
		del_nfs_ops(nfsops);
		return -rc;
	}

	cwd->fh = fhok->object;
        assert(cwd->fh.nfs_fh4_val == cwd->fhbuf);

	pthread_mutex_lock(&tc_cwd_lock);
	if (tc_cwd)
		tc_put_cwd(tc_cwd);
	tc_cwd = cwd;
	pthread_mutex_unlock(&tc_cwd_lock);

	del_nfs_ops(nfsops);
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
	ops->tc_read = ktcread;
	ops->tc_write = ktcwrite;
	ops->tc_open = ktcopen;
	ops->tc_close = ktcclose;
        ops->tc_getattrsv = tc_nfs4_getattrsv;
        ops->tc_setattrsv = tc_nfs4_setattrsv;
        ops->tc_mkdirv = tc_nfs4_mkdirv;
        ops->tc_listdirv = tc_nfs4_listdirv;
        ops->tc_renamev = tc_nfs4_renamev;
        ops->tc_removev = tc_nfs4_removev;
        ops->tc_copyv = tc_nfs4_copyv;
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
	nfs_argop4 *argoparray = NULL;
	nfs_resop4 *resoparray = NULL;
	GETFH4resok *fhok;
	struct attrlist attributes = {0};
        struct fs_obj_handle *fs_hdl;
	int opcnt = 0;
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

	argoparray = malloc((slash_cnt + 2) * sizeof(struct nfs_argop4));
	resoparray = malloc((slash_cnt + 2) * sizeof(struct nfs_resop4));

	COMPOUNDV4_ARG_ADD_OP_PUTROOTFH(opcnt, argoparray);

	p = strtok_r(pcopy, "/", &saved);
	while (p) {
		if (strcmp(p, "..") == 0) {
			/* Don't allow lookup of ".." */
			LogInfo(COMPONENT_FSAL,
				"Attempt to use \"..\" element in path %s",
				path);
			gsh_free(pcopy);
			free(resoparray);
			free(argoparray);
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

	rc = fs_nfsv4_call(op_ctx->creds, opcnt, argoparray, resoparray, NULL);
	if (rc != NFS4_OK)
		return nfsstat4_to_fsal(rc);

	fs_hdl =
	    fs_alloc_handle(op_ctx->fsal_export, &fhok->object, &attributes);
	if (fs_hdl == NULL) {
		free(resoparray);
		free(argoparray);
		return fsalstat(ERR_FSAL_FAULT, 0);
	}
	*handle = &fs_hdl->obj;

	free(resoparray);
	free(argoparray);
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
	int opcnt = 0;

#define FSAL_FSINFO_NB_OP_ALLOC 2
	nfs_argop4 argoparray[FSAL_FSINFO_NB_OP_ALLOC];
	nfs_resop4 resoparray[FSAL_FSINFO_NB_OP_ALLOC];
	GETATTR4resok *atok;
	char fattr_blob[48];	/* 6 values, 8 bytes each */
	struct fs_obj_handle *ph;

	ph = container_of(obj_hdl, struct fs_obj_handle, obj);

	COMPOUNDV4_ARG_ADD_OP_PUTFH(opcnt, argoparray, ph->fh4);
	atok =
	    fs_fill_getattr_reply(resoparray + opcnt, fattr_blob,
				   sizeof(fattr_blob));
	COMPOUNDV4_ARG_ADD_OP_GETATTR(opcnt, argoparray, fs_bitmap_fsinfo);

	rc = fs_nfsv4_call(op_ctx->creds, opcnt, argoparray, resoparray, NULL);
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

