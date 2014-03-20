/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) Panasas Inc., 2011
 * Author: Jim Lieb jlieb@panasas.com
 *
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *
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
 *
 * ------------- 
 */

/* export.c
 * VFS FSAL export object
 */

#include "config.h"

#include "fsal.h"
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <os/mntent.h>
#include <os/quota.h>
#include <dlfcn.h>
#include "nlm_list.h"
#include "fsal_convert.h"
#include "FSAL/fsal_commonlib.h"
#include "FSAL/fsal_config.h"
#include "fsal_handle_syscalls.h"
#include "secnfs_methods.h"

/* helpers to/from other VFS objects
 */

struct fsal_staticfsinfo_t *secnfs_staticinfo(struct fsal_module *hdl);
extern struct next_ops next_ops;

/********************** export object methods ********************/

static fsal_status_t release(struct fsal_export *export)
{
        fsal_status_t st = fsalstat(ERR_FSAL_NO_ERROR, 0);
        struct secnfs_fsal_export *exp = secnfs_export(export);

        /* FIXME : should I release next_fsal or not ? */
        st = next_ops.exp_ops->release(exp->next_export);
        if (FSAL_IS_ERROR(st)) {
                LogMajor(COMPONENT_FSAL, "cannot release next export (0x%p)",
                         exp->next_export);
                return st;
        }

        pthread_mutex_lock(&export->lock);
        if (export->refs > 0 || !glist_empty(&export->handles)) {
                LogMajor(COMPONENT_FSAL, "SECNFS release: export (0x%p)busy",
                         export);
                pthread_mutex_unlock(&export->lock);
                return fsalstat(posix2fsal_error(EBUSY), EBUSY);
        }
        fsal_detach_export(export->fsal, &export->exports);
        free_export_ops(export);
        pthread_mutex_unlock(&export->lock);

        pthread_mutex_destroy(&export->lock);
        gsh_free(exp);
        return st;
}

static fsal_status_t get_dynamic_info(struct fsal_export *exp_hdl,
				      const struct req_op_context *opctx,
				      fsal_dynamicfsinfo_t * infop)
{
        return next_ops.exp_ops->get_fs_dynamic_info(next_export(exp_hdl),
                                                     opctx, infop);
}

static bool fs_supports(struct fsal_export *exp_hdl,
			fsal_fsinfo_options_t option)
{
        return next_ops.exp_ops->fs_supports(next_export(exp_hdl), option);
}

static uint64_t fs_maxfilesize(struct fsal_export *exp_hdl)
{
        return next_ops.exp_ops->fs_maxfilesize(next_export(exp_hdl));
}

static uint32_t fs_maxread(struct fsal_export *exp_hdl)
{
        return next_ops.exp_ops->fs_maxread(next_export(exp_hdl));
}

static uint32_t fs_maxwrite(struct fsal_export *exp_hdl)
{
        return next_ops.exp_ops->fs_maxwrite(next_export(exp_hdl));
}

static uint32_t fs_maxlink(struct fsal_export *exp_hdl)
{
        return next_ops.exp_ops->fs_maxlink(next_export(exp_hdl));
}

static uint32_t fs_maxnamelen(struct fsal_export *exp_hdl)
{
        return next_ops.exp_ops->fs_maxnamelen(next_export(exp_hdl));
}

static uint32_t fs_maxpathlen(struct fsal_export *exp_hdl)
{
        return next_ops.exp_ops->fs_maxpathlen(next_export(exp_hdl));
}

static struct timespec fs_lease_time(struct fsal_export *exp_hdl)
{
        return next_ops.exp_ops->fs_lease_time(next_export(exp_hdl));
}

static fsal_aclsupp_t fs_acl_support(struct fsal_export *exp_hdl)
{
        return next_ops.exp_ops->fs_acl_support(next_export(exp_hdl));
}

static attrmask_t fs_supported_attrs(struct fsal_export *exp_hdl)
{
        return next_ops.exp_ops->fs_supported_attrs(next_export(exp_hdl));
}

static uint32_t fs_umask(struct fsal_export *exp_hdl)
{
        return next_ops.exp_ops->fs_umask(next_export(exp_hdl));
}

static uint32_t fs_xattr_access_rights(struct fsal_export *exp_hdl)
{
        return next_ops.exp_ops->fs_xattr_access_rights(next_export(exp_hdl));
}

/* get_quota
 * return quotas for this export.
 * path could cross a lower mount boundary which could
 * mask lower mount values with those of the export root
 * if this is a real issue, we can scan each time with setmntent()
 * better yet, compare st_dev of the file with st_dev of root_fd.
 * on linux, can map st_dev -> /proc/partitions name -> /dev/<name>
 */

static fsal_status_t get_quota(struct fsal_export *exp_hdl,
                               const char *filepath, int quota_type,
                               struct req_op_context *req_ctx,
                               fsal_quota_t * pquota)
{
        return next_ops.exp_ops->get_quota(next_export(exp_hdl), filepath,
                                           quota_type, req_ctx, pquota);
}

/* set_quota
 * same lower mount restriction applies
 */

static fsal_status_t set_quota(struct fsal_export *exp_hdl,
                               const char *filepath, int quota_type,
                               struct req_op_context *req_ctx,
                               fsal_quota_t * pquota, fsal_quota_t * presquota)
{
        return next_ops.exp_ops->set_quota(next_export(exp_hdl), filepath,
                                           quota_type, req_ctx, pquota,
                                           presquota);
}

/* extract a file handle from a buffer.
 * do verification checks and flag any and all suspicious bits.
 * Return an updated fh_desc into whatever was passed.  The most
 * common behavior, done here is to just reset the length.  There
 * is the option to also adjust the start pointer.
 */

static fsal_status_t extract_handle(struct fsal_export *exp_hdl,
                                    fsal_digesttype_t in_type,
                                    struct gsh_buffdesc *fh_desc)
{
        return next_ops.exp_ops->extract_handle(next_export(exp_hdl),
                                                in_type, fh_desc);
}

/* secnfs_export_ops_init
 * overwrite vector entries with the methods that we support
 */

void secnfs_export_ops_init(struct export_ops *ops)
{
	ops->release = release;
	ops->lookup_path = secnfs_lookup_path;
	ops->extract_handle = extract_handle;
	ops->create_handle = secnfs_create_handle;
	ops->get_fs_dynamic_info = get_dynamic_info;
	ops->fs_supports = fs_supports;
	ops->fs_maxfilesize = fs_maxfilesize;
	ops->fs_maxread = fs_maxread;
	ops->fs_maxwrite = fs_maxwrite;
	ops->fs_maxlink = fs_maxlink;
	ops->fs_maxnamelen = fs_maxnamelen;
	ops->fs_maxpathlen = fs_maxpathlen;
	ops->fs_lease_time = fs_lease_time;
	ops->fs_acl_support = fs_acl_support;
	ops->fs_supported_attrs = fs_supported_attrs;
	ops->fs_umask = fs_umask;
	ops->fs_xattr_access_rights = fs_xattr_access_rights;
	ops->get_quota = get_quota;
	ops->set_quota = set_quota;
}

void secnfs_handle_ops_init(struct fsal_obj_ops *ops);

/* create_export
 * Create an export point and return a handle to it to be kept
 * in the export list.
 * First lookup the fsal, then create the export and then put the fsal back.
 * returns the export with one reference taken.
 */

extern struct fsal_up_vector fsal_up_top;

fsal_status_t secnfs_create_export(struct fsal_module *fsal_hdl,
                                   const char *export_path,
                                   const char *fs_specific,
                                   struct exportlist *exp_entry,
                                   struct fsal_module *unused,
                                   struct fsal_up_vector *up_ops,
                                   struct fsal_export **export)
{
        fsal_status_t st;
        struct secnfs_fsal_export *exp;
        struct fsal_export *next_exp;
        struct fsal_module *next_fsal;

        exp = gsh_calloc(1, sizeof(*exp));
        if (!exp) {
                LogMajor(COMPONENT_FSAL, "Out of Memory");
                return fsalstat(ERR_FSAL_NOMEM, ENOMEM);
        }
        if (fsal_export_init(&exp->export, exp_entry)) {
                LogMajor(COMPONENT_FSAL, "Cannot init export of SECNFS");
                st = fsalstat(ERR_FSAL_NOMEM, ENOMEM);
                goto error_out;
        }

        /* We use the parameter passed as a string in fs_specific to know which
         * FSAL is to be loaded */
        next_fsal = lookup_fsal(fs_specific);
        if (next_fsal == NULL) {
                LogMajor(COMPONENT_FSAL,
                         "failed to lookup for FSAL %s", fs_specific);
                st = fsalstat(ERR_FSAL_INVAL, EINVAL);
                goto error_out;
        }

        /* FIXME: exp_entry? */
        st = next_fsal->ops->create_export(next_fsal, export_path,
                                           fs_specific, exp_entry, NULL,
                                           up_ops, &next_exp);
        if (FSAL_IS_ERROR(st)) {
                LogMajor(COMPONENT_FSAL,
                         "failed to call create_export on underlying FSAL %s",
                         fs_specific);
                goto error_out;
        }

        /* Init next_ops structure */
        /* FIXME are the memory released? It is okay for now as next_ops is a
         * static variable with only one instance. */
        next_ops.exp_ops = gsh_malloc(sizeof(struct export_ops));
        next_ops.obj_ops = gsh_malloc(sizeof(struct fsal_obj_ops));
        next_ops.ds_ops = gsh_malloc(sizeof(struct fsal_ds_ops));

        memcpy(next_ops.exp_ops, next_exp->ops, sizeof(struct export_ops));
        memcpy(next_ops.obj_ops, next_exp->obj_ops,
               sizeof(struct fsal_obj_ops));
        memcpy(next_ops.ds_ops, next_exp->ds_ops, sizeof(struct fsal_ds_ops));
        next_ops.up_ops = up_ops;

        secnfs_export_ops_init(exp->export.ops);
        secnfs_handle_ops_init(exp->export.obj_ops);
        exp->export.up_ops = up_ops;

        exp->next_export = next_exp;
        *export = &exp->export;

        return st;

error_out:
        gsh_free(exp);
        return st;
}
