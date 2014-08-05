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

#include "config.h"

#include "fsal.h"
#include "fsal_handle_syscalls.h"
#include <libgen.h>		/* used for 'dirname' */
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include "nlm_list.h"
#include "fsal_convert.h"
#include "FSAL/fsal_commonlib.h"
#include "secnfs_methods.h"
#include <os/subr.h>

#define PASS_DOWN(func, obj_hdl, args...)                                   \
        struct fsal_obj_handle *next_hdl = next_handle(obj_hdl);            \
        fsal_status_t st = next_ops.obj_ops->func(next_hdl, ## args);       \
        if (!FSAL_IS_ERROR(st)) {                                           \
                adjust_attributes_up(obj_hdl, next_hdl);                    \
        }                                                                   \
        return st;


#define MAKE_SECNFS_FH(func, parent, handle, args...)                       \
        struct secnfs_fsal_obj_handle *hdl = secnfs_handle(parent);         \
        struct fsal_obj_handle *next_hdl;                                   \
        fsal_status_t st;                                                   \
        st = next_ops.obj_ops->func(hdl->next_handle, ## args, &next_hdl);  \
        if (FSAL_IS_ERROR(st)) {                                            \
                LogCrit(COMPONENT_FSAL, "secnfs " #func " failed");         \
                return st;                                                  \
        }                                                                   \
        return make_handle_from_next(parent->export, opctx, next_hdl, handle);


extern struct next_ops next_ops;

/************************* helpers **********************/

static struct secnfs_fsal_obj_handle *alloc_handle(struct fsal_export *exp,
                                                   const struct attrlist *attr)
{
        struct secnfs_fsal_module *secnfs_fsal = secnfs_module(exp->fsal);
        struct secnfs_fsal_obj_handle *hdl;
        fsal_status_t st;

        hdl = gsh_calloc(1, sizeof(*hdl));
        if (hdl == NULL)
                return NULL;

        hdl->obj_handle.attributes = *attr;
        hdl->info = &secnfs_fsal->secnfs_info;

        if (fsal_obj_handle_init(&hdl->obj_handle, exp, attr->type)) {
                gsh_free(hdl);
                return NULL;
        }

        return hdl;
}


static void adjust_attributes_up(struct fsal_obj_handle *obj_hdl,
                                 struct fsal_obj_handle *next_hdl)
{
        if (obj_hdl->type == REGULAR_FILE) {
                /* preserve effective filesize */
                uint64_t effective_size = obj_hdl->attributes.filesize;
                obj_hdl->attributes = next_hdl->attributes;
                obj_hdl->attributes.filesize = effective_size;
        } else {
                obj_hdl->attributes = next_hdl->attributes;
        }
}


static void adjust_attributes_down(struct attrlist *attr,
                                   object_file_type_t type)
{
        if (type == REGULAR_FILE && (attr->mask & ATTR_SIZE))
                attr->filesize = pi_round_up(attr->filesize) + FILE_HEADER_SIZE;
}


/**
 * Create a SECNFS obj handle from a corresponding handle of the next layer.
 *
 * @param[IN]       exp      SECNFS export
 * @param[IN]       opctx    request op context
 * @param[IN/OUT]   next_hdl handle of the next layer
 * @param[OUT]      handle   resultant SECNFS handle
 *
 * NOTE: next_hdl will be released on failure!
 */
static fsal_status_t make_handle_from_next(struct fsal_export *exp,
                                           const struct req_op_context *opctx,
                                           struct fsal_obj_handle *next_hdl,
                                           struct fsal_obj_handle **handle)
{
        struct secnfs_fsal_obj_handle *secnfs_hdl;
        fsal_status_t st;

        secnfs_hdl = alloc_handle(exp, &next_hdl->attributes);
        if (!secnfs_hdl) {
                LogMajor(COMPONENT_FSAL, "cannot allocate secnfs handle");
                next_ops.obj_ops->release(next_hdl);
                return fsalstat(ERR_FSAL_NOMEM, 0);
        }

        secnfs_hdl->next_handle = next_hdl;
        *handle = &secnfs_hdl->obj_handle;

        if (next_hdl->type == REGULAR_FILE) {
                if (!(secnfs_hdl->range_lock = secnfs_alloc_blockmap()) ||
                        !(secnfs_hdl->holes = secnfs_alloc_blockmap())) {
                        st = fsalstat(ERR_FSAL_NOMEM, 0);
                        goto err;
                }

                if (next_hdl->attributes.filesize > 0) {
                        SECNFS_D("hdl = %x; reading header\n", secnfs_hdl);
                        st = read_header(*handle, opctx);
                        if (FSAL_IS_ERROR(st))
                                goto err;
                        SECNFS_D("hdl = %x; file encrypted: %d\n",
                                 secnfs_hdl, secnfs_hdl->encrypted);
                }
        }

        return fsalstat(ERR_FSAL_NO_ERROR, 0);

err:
        LogMajor(COMPONENT_FSAL, "cannot allocate secnfs handle");
        secnfs_release_blockmap(&secnfs_hdl->range_lock);
        secnfs_release_blockmap(&secnfs_hdl->holes);
        gsh_free(secnfs_hdl);
        next_ops.obj_ops->release(next_hdl);

        return st;
}


/************************* handle methods **********************/

/* lookup
 * deprecated NULL parent && NULL path implies root handle
 */
static fsal_status_t lookup(struct fsal_obj_handle *parent,
			    const struct req_op_context *opctx,
			    const char *path, struct fsal_obj_handle **handle)
{
        MAKE_SECNFS_FH(lookup, parent, handle, opctx, path);
}


fsal_status_t read_header(struct fsal_obj_handle *fsal_hdl,
                          const struct req_op_context *opctx)
{
        struct secnfs_fsal_obj_handle *hdl = secnfs_handle(fsal_hdl);
        fsal_status_t st;
        void *buf;
        uint32_t buf_size, header_len;
        size_t n, read_amount = 0;
        bool end_of_file = false;
        uint64_t filesize;
        secnfs_s ret;

        buf_size = FILE_HEADER_SIZE;
        buf = gsh_malloc(buf_size);
        assert(buf);

        do {
                st = next_ops.obj_ops->read(hdl->next_handle,
                                            opctx,
                                            read_amount,
                                            buf_size - read_amount,
                                            buf + read_amount,
                                            &n,
                                            &end_of_file);
                if (FSAL_IS_ERROR(st)) {
                        LogCrit(COMPONENT_FSAL, "cannot read secnfs header");
                        goto out;
                }

                read_amount += n;

                if (read_amount < FILE_HEADER_SIZE && end_of_file) {
                        st = fsalstat(ERR_FSAL_IO, 0);
                        LogCrit(COMPONENT_FSAL, "invalid secnfs header size");
                        goto out;
                }
        } while (read_amount < FILE_HEADER_SIZE);

        ret = secnfs_read_header(hdl->info,
                                 buf,
                                 buf_size,
                                 &hdl->fk,
                                 &hdl->iv,
                                 &filesize,
                                 &hdl->encrypted,
                                 hdl->holes,
                                 &header_len,
                                 &hdl->kf_cache);
        assert(ret == SECNFS_OKAY);

        fsal_hdl->attributes.filesize = filesize;

        hdl->key_initialized = 1;

out:
        gsh_free(buf);
        return st;
}


fsal_status_t write_header(struct fsal_obj_handle *fsal_hdl,
                           const struct req_op_context *opctx)
{
        struct secnfs_fsal_obj_handle *hdl = secnfs_handle(fsal_hdl);
        fsal_status_t st;
        uint32_t buf_size;
        size_t n, write_amount = 0;
        void *buf;
        int ret;
        bool stable;

        ret = secnfs_create_header(hdl->info, &hdl->fk, &hdl->iv,
                                   get_filesize(hdl),
                                   hdl->encrypted,
                                   hdl->holes,
                                   &buf, &buf_size, &hdl->kf_cache);

        assert(ret == SECNFS_OKAY);
        assert(buf_size == FILE_HEADER_SIZE);

        hdl->data_offset = buf_size;

        do {
                st = next_ops.obj_ops->write(hdl->next_handle, opctx,
                                             write_amount,
                                             buf_size - write_amount,
                                             buf + write_amount,
                                             &n,
                                             &stable);
                if (FSAL_IS_ERROR(st)) {
                        LogCrit(COMPONENT_FSAL, "cannot write secnfs header");
                        goto out;
                }
                write_amount += n;
        } while (write_amount < buf_size);

        hdl->has_dirty_meta = 0;

out:
        free(buf);
        return st;
}


static fsal_status_t create(struct fsal_obj_handle *dir_hdl,
                            const struct req_op_context *opctx,
                            const char *name, struct attrlist *attrib,
                            struct fsal_obj_handle **handle)
{
        struct secnfs_fsal_obj_handle *hdl = secnfs_handle(dir_hdl);
        struct fsal_obj_handle *next_hdl;
        struct secnfs_fsal_obj_handle *new_hdl;
        fsal_status_t st;

        SECNFS_D("CREATING '%s' in dir hdl (%x)", name, hdl);

        st = next_ops.obj_ops->create(hdl->next_handle, opctx, name,
                                      attrib, &next_hdl);
        if (FSAL_IS_ERROR(st))
                return st;

        st = make_handle_from_next(dir_hdl->export, opctx, next_hdl, handle);
        if (FSAL_IS_ERROR(st)) {
                LogCrit(COMPONENT_FSAL, "cannot create secnfs handle");
                return st;
        }

        if (attrib->type == REGULAR_FILE) {
                new_hdl = secnfs_handle(*handle);
                generate_key_and_iv(&new_hdl->fk, &new_hdl->iv);
                new_hdl->key_initialized = 1;
                new_hdl->has_dirty_meta = 0;
                 /* TODO mechanism to enable / disable encryption */
                new_hdl->encrypted = 0;
                SECNFS_D("key in new handle (%x) initialized; encryption %s",
                         new_hdl, new_hdl->encrypted ? "enabled" : "disabled");
                st = write_header(*handle, opctx);
        }

        return st;
}


static fsal_status_t makedir(struct fsal_obj_handle *dir_hdl,
			     const struct req_op_context *opctx,
			     const char *name, struct attrlist *attrib,
			     struct fsal_obj_handle **handle)
{
        MAKE_SECNFS_FH(mkdir, dir_hdl, handle, opctx, name, attrib);
}

static fsal_status_t makenode(struct fsal_obj_handle *dir_hdl,
                              const struct req_op_context *opctx,
                              const char *name, object_file_type_t nodetype,	/* IN */
			      fsal_dev_t * dev,	/* IN */
			      struct attrlist *attrib,
			      struct fsal_obj_handle **handle)
{
        MAKE_SECNFS_FH(mknode, dir_hdl, handle, opctx, name,
                       nodetype, dev, attrib);
}

/** makesymlink
 *  Note that we do not set mode bits on symlinks for Linux/POSIX
 *  They are not really settable in the kernel and are not checked
 *  anyway (default is 0777) because open uses that target's mode
 */

static fsal_status_t makesymlink(struct fsal_obj_handle *dir_hdl,
				 const struct req_op_context *opctx,
				 const char *name, const char *link_path,
				 struct attrlist *attrib,
				 struct fsal_obj_handle **handle)
{
        MAKE_SECNFS_FH(symlink, dir_hdl, handle, opctx, name,
                       link_path, attrib);
}


static fsal_status_t readsymlink(struct fsal_obj_handle *obj_hdl,
				 const struct req_op_context *opctx,
				 struct gsh_buffdesc *link_content,
				 bool refresh)
{
        return next_ops.obj_ops->readlink(next_handle(obj_hdl), opctx,
                                          link_content, refresh);
}


static fsal_status_t linkfile(struct fsal_obj_handle *obj_hdl,
			      const struct req_op_context *opctx,
			      struct fsal_obj_handle *destdir_hdl,
			      const char *name)
{
        return next_ops.obj_ops->link(next_handle(obj_hdl), opctx,
                                      next_handle(destdir_hdl), name);
}

/**
 * read_dirents
 * read the directory and call through the callback function for
 * each entry.
 * @param dir_hdl [IN] the directory to read
 * @param whence [IN] where to start (next)
 * @param dir_state [IN] pass thru of state to callback
 * @param cb [IN] callback function
 * @param eof [OUT] eof marker true == end of dir
 */

static fsal_status_t read_dirents(struct fsal_obj_handle *dir_hdl,
                                  const struct req_op_context *opctx,
                                  fsal_cookie_t *whence, void *dir_state,
                                  fsal_readdir_cb cb, bool *eof)
{
        return next_ops.obj_ops->readdir(next_handle(dir_hdl), opctx,
                                         whence, dir_state, cb, eof);
}


static fsal_status_t renamefile(struct fsal_obj_handle *olddir_hdl,
				const struct req_op_context *opctx,
				const char *old_name,
				struct fsal_obj_handle *newdir_hdl,
				const char *new_name)
{
        return next_ops.obj_ops->rename(next_handle(olddir_hdl),
                                        opctx, old_name,
                                        next_handle(newdir_hdl),
                                        new_name);
}


static fsal_status_t getattrs(struct fsal_obj_handle *obj_hdl,
			      const struct req_op_context *opctx)
{
        PASS_DOWN(getattrs, obj_hdl, opctx);
}


/*
 * NOTE: this is done under protection of the attributes rwlock in the cache entry.
 */
static fsal_status_t setattrs(struct fsal_obj_handle *obj_hdl,
			      const struct req_op_context *opctx,
			      struct attrlist *attrs)
{
        if (attrs->mask & ATTR_SIZE && obj_hdl->type == REGULAR_FILE) {
                fsal_status_t st;
                st = secnfs_truncate(obj_hdl, opctx, attrs->filesize);
                if (FSAL_IS_ERROR(st)) {
                        LogCrit(COMPONENT_FSAL, "truncate failed");
                        return st;
                }
        }

        /*
         * We use the "obj_hdl->type", instead of "attrs->type" because,
         * sometimes, "attrs->type" is NO_FILE_TYPE.  For example, when
         * we "truncate" a file.
         */
        adjust_attributes_down(attrs, obj_hdl->type);
        PASS_DOWN(setattrs, obj_hdl, opctx, attrs);
}


/* file_unlink
 * unlink the named file in the directory
 */
static fsal_status_t file_unlink(struct fsal_obj_handle *dir_hdl,
				 const struct req_op_context *opctx,
				 const char *name)
{
        SECNFS_D("Unlink %s", name);
        return next_ops.obj_ops->unlink(next_handle(dir_hdl), opctx, name);
}


/* handle_digest
 * fill in the opaque f/s file handle part.
 * we zero the buffer to length first.  This MAY already be done above
 * at which point, remove memset here because the caller is zeroing
 * the whole struct.
 */
static fsal_status_t handle_digest(const struct fsal_obj_handle *obj_hdl,
				   fsal_digesttype_t output_type,
				   struct gsh_buffdesc *fh_desc)
{
        struct fsal_obj_handle *hdl = (struct fsal_obj_handle *)obj_hdl;

        return next_ops.obj_ops->handle_digest(next_handle(hdl),
                                               output_type, fh_desc);
}


/**
 * handle_to_key
 * return a handle descriptor into the handle in this object handle
 * @TODO reminder.  make sure things like hash keys don't point here
 * after the handle is released.
 */
static void handle_to_key(struct fsal_obj_handle *obj_hdl,
			  struct gsh_buffdesc *fh_desc)
{
        return next_ops.obj_ops->handle_to_key(next_handle(obj_hdl), fh_desc);
}


/*
 * release
 * release our export first so they know we are gone
 */
static fsal_status_t release(struct fsal_obj_handle *obj_hdl)
{
        struct secnfs_fsal_obj_handle *secnfs_hdl = secnfs_handle(obj_hdl);
        struct fsal_obj_handle *next_hdl;
        int retval;

        next_hdl = secnfs_hdl->next_handle;

        retval = fsal_obj_handle_uninit(obj_hdl);
        if (retval != 0) {
                LogCrit(COMPONENT_FSAL,
                        "Tried to release busy handle @ %p with %d refs",
                        obj_hdl, obj_hdl->refs);
                return fsalstat(ERR_FSAL_DELAY, EBUSY);
        }

        secnfs_release_keyfile_cache(&secnfs_hdl->kf_cache);
        secnfs_release_blockmap(&secnfs_hdl->range_lock);
        secnfs_release_blockmap(&secnfs_hdl->holes);
        gsh_free(secnfs_hdl);

	return next_ops.obj_ops->release(next_hdl);
}


void secnfs_handle_ops_init(struct fsal_obj_ops *ops)
{
	ops->release = release;
	ops->lookup = lookup;
	ops->readdir = read_dirents;
	ops->create = create;
	ops->mkdir = makedir;
	ops->mknode = makenode;
	ops->symlink = makesymlink;
	ops->readlink = readsymlink;
	ops->test_access = fsal_test_access;
	ops->getattrs = getattrs;
	ops->setattrs = setattrs;
	ops->link = linkfile;
	ops->rename = renamefile;
	ops->unlink = file_unlink;
	ops->open = secnfs_open;
	ops->status = secnfs_status;
	ops->read = secnfs_read;
	ops->write = secnfs_write;
	ops->commit = secnfs_commit;
	ops->lock_op = secnfs_lock_op;
	ops->close = secnfs_close;
	ops->lru_cleanup = secnfs_lru_cleanup;
	ops->handle_digest = handle_digest;
	ops->handle_to_key = handle_to_key;

	/* xattr related functions */
	ops->list_ext_attrs = secnfs_list_ext_attrs;
	ops->getextattr_id_by_name = secnfs_getextattr_id_by_name;
	ops->getextattr_value_by_name = secnfs_getextattr_value_by_name;
	ops->getextattr_value_by_id = secnfs_getextattr_value_by_id;
	ops->setextattr_value = secnfs_setextattr_value;
	ops->setextattr_value_by_id = secnfs_setextattr_value_by_id;
	ops->getextattr_attrs = secnfs_getextattr_attrs;
	ops->remove_extattr_by_id = secnfs_remove_extattr_by_id;
	ops->remove_extattr_by_name = secnfs_remove_extattr_by_name;

}


/* lookup_path
 * modeled on old api except we don't stuff attributes.
 * KISS
 */
fsal_status_t secnfs_lookup_path(struct fsal_export *exp_hdl,
                                 const struct req_op_context *opctx,
                                 const char *path,
                                 struct fsal_obj_handle **handle)
{
        struct secnfs_fsal_export *exp = secnfs_export(exp_hdl);
        struct fsal_obj_handle *next_hdl;
        fsal_status_t st;

        st = next_ops.exp_ops->lookup_path(exp->next_export, opctx,
                                           path, &next_hdl);
        if (FSAL_IS_ERROR(st)) {
                return st;
        }

        return make_handle_from_next(exp_hdl, opctx, next_hdl, handle);
}


/* create_handle
 * Does what original FSAL_ExpandHandle did (sort of)
 * returns a ref counted handle to be later used in cache_inode etc.
 * NOTE! you must release this thing when done with it!
 * BEWARE! Thanks to some holes in the *AT syscalls implementation,
 * we cannot get an fd on an AF_UNIX socket, nor reliably on block or
 * character special devices.  Sorry, it just doesn't...
 * we could if we had the handle of the dir it is in, but this method
 * is for getting handles off the wire for cache entries that have LRU'd.
 * Ideas and/or clever hacks are welcome...
 */
fsal_status_t secnfs_create_handle(struct fsal_export *exp,
                                   const struct req_op_context *opctx,
                                   struct gsh_buffdesc *hdl_desc,
                                   struct fsal_obj_handle **handle)
{
        fsal_status_t st;
        struct fsal_obj_handle *next_hdl;
        struct secnfs_fsal_export *secnfs_exp = secnfs_export(exp);

        st = next_ops.exp_ops->create_handle(secnfs_exp->next_export, opctx,
                                             hdl_desc, &next_hdl);
        if (FSAL_IS_ERROR(st)) {
                SECNFS_ERR("cannot create next handle (%d, %d)",
                           st.major, st.minor);
                return st;
        }

        SECNFS_F("handle created by secnfs_create_handle\n");

        return make_handle_from_next(exp, opctx, next_hdl, handle);
}
