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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * -------------
 */

/* file.c
 * File I/O methods for VFS module
 */

#include "config.h"

#include <assert.h>
#include "fsal.h"
#include "FSAL/access_check.h"
#include "fsal_convert.h"
#include <unistd.h>
#include <fcntl.h>
#include "FSAL/fsal_commonlib.h"
#include "secnfs_methods.h"
#include "fsal_handle_syscalls.h"
#include "secnfs.h"

extern struct next_ops next_ops;

static bool should_read_header(const struct secnfs_fsal_obj_handle *hdl)
{
        return hdl->obj_handle.type == REGULAR_FILE
                && hdl->obj_handle.attributes.filesize > 0
                && !hdl->key_initialized;
}


/** secnfs_open
 * called with appropriate locks taken at the cache inode level
 */
fsal_status_t secnfs_open(struct fsal_obj_handle *obj_hdl,
                          const struct req_op_context *opctx,
                          fsal_openflags_t openflags)
{
        struct secnfs_fsal_obj_handle *hdl = secnfs_handle(obj_hdl);
        fsal_status_t st;

        SECNFS_D("hdl = %x; openflag = %d\n", hdl, openflags);

        st = next_ops.obj_ops->open(hdl->next_handle, opctx, openflags);

        if (!FSAL_IS_ERROR(st) && should_read_header(hdl)) {
                // read file key, iv and meta
                st = read_header(obj_hdl, opctx);
        }

        return st;
}


/* secnfs_status
 * Let the caller peek into the file's open/close state.
 */
fsal_openflags_t secnfs_status(struct fsal_obj_handle *obj_hdl)
{
        return next_ops.obj_ops->status(next_handle(obj_hdl));
}


inline fsal_status_t secnfs_to_fsal_status(secnfs_s s) {
        fsal_status_t fsal_s;

        if (s == SECNFS_OKAY) {
                fsal_s.major = ERR_FSAL_NO_ERROR;
                fsal_s.minor = 0;
        } else {
                fsal_s.major = ERR_FSAL_IO;
                fsal_s.minor = s;
        }

        return fsal_s;
}

inline secnfs_s read_update_one(uint8_t *dst, void *src,
                                uint64_t dst_offset, size_t src_size,
                                uint64_t file_offset,
                                struct secnfs_fsal_obj_handle *hdl,
                                const struct req_op_context *opctx)
{
        fsal_status_t st;
        size_t read_amount;
        bool end_of_file;
        assert(dst_offset + src_size <= PI_INTERVAL_SIZE);
        assert(is_pi_aligned(file_offset));

        if (dst_offset == 0 && src_size == PI_INTERVAL_SIZE)
                goto update;

        if (file_offset < get_filesize(hdl)) {
                SECNFS_D("hdl = %x; READ remote block for update", hdl);
                st = secnfs_read(&hdl->obj_handle,
                                opctx, file_offset,
                                PI_INTERVAL_SIZE, dst,
                                &read_amount, &end_of_file);

                if (FSAL_IS_ERROR(st))
                        return SECNFS_READ_UPDATE_FAIL;

                if (read_amount == 0) {
                        if (end_of_file) {
                                /* remote returned empty & EOF, continue */
                                memset(dst, 0, PI_INTERVAL_SIZE);
                        } else {
                                /* probably partial read, abort */
                                return SECNFS_READ_UPDATE_FAIL;
                        }

                }
        } else {
                /* extending the file: need not to read, but to fill zero */
                memset(dst, 0, PI_INTERVAL_SIZE);
        }

update:
        memcpy(dst + dst_offset, src, src_size);

        return SECNFS_OKAY;
}

/*
 * concurrency (locks) is managed in cache_inode_*
 */
fsal_status_t secnfs_read(struct fsal_obj_handle *obj_hdl,
                          const struct req_op_context *opctx, uint64_t offset,
                          size_t buffer_size, void *buffer,
                          size_t *read_amount, bool *end_of_file)
{
        struct secnfs_fsal_obj_handle *hdl = secnfs_handle(obj_hdl);
        fsal_status_t st;
        uint64_t next_offset; /* include file header */
        uint64_t offset_align;
        uint64_t offset_moved;
        size_t size_align;
        struct data_plus data_plus;
        struct secnfs_dif secnfs_dif;
        uint8_t *secnfs_dif_buf = NULL;
        void *pd_buf = NULL;
        void *pi_buf = NULL;
        size_t pi_size;
        bool align;
        int i;

        SECNFS_D("hdl = %x; read from %u (%u)\n", hdl, offset, buffer_size);

        if (obj_hdl->type != REGULAR_FILE) {
                return next_ops.obj_ops->read(hdl->next_handle, opctx,
                                              offset,
                                              buffer_size, buffer,
                                              read_amount, end_of_file);
        }

        /* avoid unnecessary read */
        if (offset >= get_filesize(hdl)) {
                *read_amount = 0;
                *end_of_file = 1;
                return fsalstat(ERR_FSAL_NO_ERROR, 0);
        }

        offset_align = round_down(offset, PI_INTERVAL_SIZE);
        offset_moved = offset - offset_align;
        next_offset = offset_align + FILE_HEADER_SIZE;
        size_align = round_up(offset + buffer_size, PI_INTERVAL_SIZE)
                        - offset_align;
        align = (offset == offset_align && buffer_size == size_align) ? 1 : 0;

        SECNFS_D("hdl = %x; offset_align = %u, size_align = %u",
                 hdl, offset_align, size_align);
        assert(hdl->key_initialized);
        assert(offset_moved < PI_INTERVAL_SIZE);

        /* To use read_plus, a struct data_plus need be prepared. */
        pi_size = get_pi_size(size_align);
        pi_buf = gsh_malloc(pi_size);
        if (pi_buf == NULL) {
                st = fsalstat(ERR_FSAL_NOMEM, 0);
                goto out;
        }

        pd_buf = align ? buffer : gsh_malloc(size_align);
        if (pd_buf == NULL) {
                st = fsalstat(ERR_FSAL_NOMEM, 0);
                goto out;
        }
        data_plus_type_protected_data_init(&data_plus, next_offset,
                                           pi_size, pi_buf,
                                           size_align, pd_buf);

        st = next_ops.obj_ops->read_plus(hdl->next_handle,
                                         opctx,
                                         next_offset, size_align,
                                         pd_buf, read_amount,
                                         &data_plus,
                                         end_of_file);

        if (FSAL_IS_ERROR(st))
                goto out;

        SECNFS_D("hdl = %x; read_amount = %u", hdl, *read_amount);
        *read_amount = round_down(*read_amount, PI_INTERVAL_SIZE);
        SECNFS_D("hdl = %x; read_amount_align = %u", hdl, *read_amount);
        SECNFS_D("hdl = %x; pd_info_len = %u", hdl,
                        data_plus_to_pi_dlen(&data_plus));
        dump_pi_buf(pi_buf, data_plus_to_pi_dlen(&data_plus));

        secnfs_dif_buf = gsh_malloc(PI_SECNFS_DIF_SIZE);
        if (pi_buf == NULL) {
                st = fsalstat(ERR_FSAL_NOMEM, 0);
                goto out;
        }

        for (i = 0; i < get_pi_count(*read_amount); i++) {
                extract_from_sd_dif(pi_buf + PI_DIF_HEADER_SIZE
                                    + i * PI_SD_DIF_SIZE, secnfs_dif_buf,
                                    PI_SECNFS_DIF_SIZE, 1);
                secnfs_dif_from_buf(&secnfs_dif, secnfs_dif_buf);

                SECNFS_D("hdl = %x; ver(%u) = %llx",
                         hdl, i + (offset_align >> PI_INTERVAL_SHIFT),
                         secnfs_dif.version);
                SECNFS_D("hdl = %x; tag(%u) = %02x...%02x",
                         hdl, i + (offset_align >> PI_INTERVAL_SHIFT),
                         secnfs_dif.tag[0], secnfs_dif.tag[15]);

                /* may carefully decrypt to 'buffer' to save memcpy */
                secnfs_s ret = secnfs_verify_decrypt(
                                        hdl->fk,
                                        hdl->iv,
                                        offset_align + i * PI_INTERVAL_SIZE,
                                        PI_INTERVAL_SIZE,
                                        pd_buf + i * PI_INTERVAL_SIZE,
                                        VERSION_SIZE,
                                        &(secnfs_dif.version),
                                        secnfs_dif.tag,
                                        pd_buf + i * PI_INTERVAL_SIZE);

                if (ret != SECNFS_OKAY) {
                        SECNFS_D("hdl = %x; ret(%u) = %d", hdl, i, ret);
                        st = secnfs_to_fsal_status(ret);
                        goto out;
                }
        }

        /* update effective read_amount to user */
        if (*read_amount > 0) {
                *read_amount = (*read_amount == size_align) ?
                               buffer_size : *read_amount - offset_moved;

                /* user's buffer_size may be larger than effective amount */
                if (offset + *read_amount > get_filesize(hdl)) {
                        /* if EOF is not set, effective filesize in header
                         * does not match the real size on remote disk. */
                        if (!*end_of_file) {
                                SECNFS_I("hdl = %x; size unsynchronized?", hdl);
                                *end_of_file = 1;
                        }
                        *read_amount = get_filesize(hdl) - offset;
                        assert(*read_amount > 0);
                }

                if (!align)
                        memcpy(buffer, pd_buf + offset_moved, *read_amount);
        }

        /* clear inaccurate EOF flag */
        if (*end_of_file && offset + *read_amount < get_filesize(hdl))
                *end_of_file = 0;

        st = secnfs_to_fsal_status(SECNFS_OKAY);

out:
        if (!align) gsh_free(pd_buf);
        gsh_free(pi_buf);
        gsh_free(secnfs_dif_buf);

        return st;
}

/* secnfs_write
 * concurrency (locks) is managed in cache_inode_*
 */
fsal_status_t secnfs_write(struct fsal_obj_handle *obj_hdl,
                           const struct req_op_context *opctx, uint64_t offset,
                           size_t buffer_size, void *buffer,
                           size_t *write_amount, bool *fsal_stable)
{
        struct secnfs_fsal_obj_handle *hdl = secnfs_handle(obj_hdl);
        uint64_t next_offset;
        uint64_t offset_align;
        uint64_t offset_moved;
        uint64_t size_align;
        struct data_plus data_plus;
        uint8_t *plain_align = NULL;
        uint8_t *pd_buf = NULL;
        uint8_t *pi_buf = NULL;
        uint64_t pi_count;
        size_t pi_size;
        struct secnfs_dif secnfs_dif = {0};
        uint8_t *secnfs_dif_buf = NULL;
        fsal_status_t st;
        secnfs_s ret;
        bool align;
        int i;

        SECNFS_D("hdl = %x; write to %u (%u)\n", hdl, offset, buffer_size);

        if (obj_hdl->type != REGULAR_FILE) {
                return next_ops.obj_ops->write(hdl->next_handle, opctx,
                                               offset,
                                               buffer_size, buffer,
                                               write_amount,
                                               fsal_stable);
        }

        if (buffer_size == 0)
                return fsalstat(ERR_FSAL_NO_ERROR, 0);

        offset_align = round_down(offset, PI_INTERVAL_SIZE);
        offset_moved = offset - offset_align;
        next_offset = offset_align + FILE_HEADER_SIZE;
        size_align = round_up(offset + buffer_size, PI_INTERVAL_SIZE)
                        - offset_align;
        align = (offset == offset_align && buffer_size == size_align) ? 1 : 0;

        SECNFS_D("hdl = %x; offset_align = %u, size_align = %u",
                 hdl, offset_align, size_align);
        SECNFS_D("hdl = %x; key = %d\n", hdl, hdl->key_initialized);
        assert(hdl->key_initialized);
        assert(offset_moved < PI_INTERVAL_SIZE);

        /* allocate buffer for plain text */
        plain_align = align ? buffer : gsh_malloc(size_align);
        if (plain_align == NULL) {
                st = fsalstat(ERR_FSAL_NOMEM, 0);
                goto out;
        }

        if (!align) {
                /* prepare first block */
                pi_count = get_pi_count(size_align);
                ret = read_update_one(plain_align,
                                buffer,
                                offset_moved,
                                pi_count == 1 ?
                                buffer_size : PI_INTERVAL_SIZE - offset_moved,
                                offset_align,
                                hdl, opctx);

                if (ret != SECNFS_OKAY) {
                        st = secnfs_to_fsal_status(ret);
                        goto out;
                }

                if (pi_count > 1) {
                        /* prepare last block */
                        uint64_t tail_offset; /* relative offset */
                        tail_offset = (pi_count - 1) * PI_INTERVAL_SIZE;

                        ret = read_update_one(
                                plain_align + tail_offset,
                                buffer - offset_moved + tail_offset,
                                0,
                                offset_moved + buffer_size - tail_offset,
                                offset_align + tail_offset,
                                hdl, opctx);

                        if (ret != SECNFS_OKAY) {
                                st = secnfs_to_fsal_status(ret);
                                goto out;
                        }

                        /* prepare intermediate blocks */
                        if (pi_count > 2) {
                        /* may save this copy by loop auth_encrypt carefully */
                                memcpy(plain_align + PI_INTERVAL_SIZE,
                                buffer - offset_moved + PI_INTERVAL_SIZE,
                                (pi_count - 2) * PI_INTERVAL_SIZE);
                        }
                }
        }

        /* allocate buffer for ciphertext */
        pd_buf = gsh_malloc(size_align + TAG_SIZE);
        if (pd_buf == NULL) {
                st = fsalstat(ERR_FSAL_NOMEM, 0);
                goto out;
        }

        /* allocate buffer for protection info (DIF) */
        pi_size = get_pi_size(size_align);
        pi_buf = gsh_malloc(pi_size);
        SECNFS_D("hdl = %x; pi_size = %u\n", hdl, pi_size);
        if (pi_buf == NULL) {
                st = fsalstat(ERR_FSAL_NOMEM, 0);
                goto out;
        }
        memset(pi_buf, 0, PI_DIF_HEADER_SIZE);
        pi_buf[0] = GENERATE_GUARD; /* required DIF header */

        /* allocate buffer for serialization of secnfs_dif_t */
        secnfs_dif_buf = gsh_malloc(PI_SECNFS_DIF_SIZE);
        if (pi_buf == NULL) {
                st = fsalstat(ERR_FSAL_NOMEM, 0);
                goto out;
        }

        secnfs_dif.version = 0x1234567890abcdef;
        for (i = 0; i < get_pi_count(size_align); i++) {
                ret = secnfs_auth_encrypt(
                                hdl->fk,
                                hdl->iv,
                                offset_align + i * PI_INTERVAL_SIZE,
                                PI_INTERVAL_SIZE,
                                plain_align + i * PI_INTERVAL_SIZE,
                                VERSION_SIZE,
                                &secnfs_dif.version,
                                pd_buf + i * PI_INTERVAL_SIZE,
                                secnfs_dif.tag);

                if (ret != SECNFS_OKAY) {
                        st = secnfs_to_fsal_status(ret);
                        goto out;
                }

                SECNFS_D("hdl = %x; ver(%u) = %llx",
                         hdl, i + (offset_align >> PI_INTERVAL_SHIFT),
                         secnfs_dif.version);
                SECNFS_D("hdl = %x; tag(%u) = %02x...%02x",
                         hdl, i + (offset_align >> PI_INTERVAL_SHIFT),
                         secnfs_dif.tag[0], secnfs_dif.tag[15]);

                secnfs_dif_to_buf(&secnfs_dif, secnfs_dif_buf);
                fill_sd_dif(pi_buf + PI_DIF_HEADER_SIZE + i * PI_SD_DIF_SIZE,
                                secnfs_dif_buf, PI_SECNFS_DIF_SIZE, 1);
        }
        dump_pi_buf(pi_buf, pi_size);

        /* prepare data_plus for write_plus */
        data_plus_type_protected_data_init(&data_plus, next_offset,
                                           pi_size, pi_buf,
                                           size_align, pd_buf);

        st = next_ops.obj_ops->write_plus(hdl->next_handle,
                                          opctx,
                                          next_offset, size_align,
                                          pd_buf, write_amount,
                                          &data_plus,
                                          fsal_stable);

        *write_amount = round_down(*write_amount, PI_INTERVAL_SIZE);
        *write_amount = (*write_amount == size_align) ?
                        buffer_size : *write_amount - offset_moved;

        if (offset + *write_amount > get_filesize(hdl))
                update_filesize(hdl, offset + *write_amount);

        SECNFS_D("hdl = %x; client_size = %d; write_amount = %d\n", obj_hdl,
                        obj_hdl->attributes.filesize, *write_amount);
out:
        if (!align) gsh_free(plain_align);
        gsh_free(pd_buf);
        gsh_free(pi_buf);
        gsh_free(secnfs_dif_buf);

        return st;
}


/* secnfs_commit
 * Commit a file range to storage.
 * for right now, fsync will have to do.
 */
fsal_status_t secnfs_commit(struct fsal_obj_handle *obj_hdl,    /* sync */
                            off_t offset, size_t len)
{
        return next_ops.obj_ops->commit(next_handle(obj_hdl), offset, len);
}


/* secnfs_lock_op
 * lock a region of the file
 * throw an error if the fd is not open.  The old fsal didn't
 * check this.
 */
fsal_status_t secnfs_lock_op(struct fsal_obj_handle *obj_hdl,
                             const struct req_op_context *opctx, void *p_owner,
                             fsal_lock_op_t lock_op,
                             fsal_lock_param_t *request_lock,
                             fsal_lock_param_t *conflicting_lock)
{
        return next_ops.obj_ops->lock_op(next_handle(obj_hdl), opctx, p_owner,
                                         lock_op, request_lock,
                                         conflicting_lock);
}


/* secnfs_close
 * Close the file if it is still open.
 * Yes, we ignor lock status.  Closing a file in POSIX
 * releases all locks but that is state and cache inode's problem.
 */
fsal_status_t secnfs_close(struct fsal_obj_handle *obj_hdl)
{
        struct secnfs_fsal_obj_handle *hdl = secnfs_handle(obj_hdl);

        if (obj_hdl->type == REGULAR_FILE && hdl->has_dirty_meta) {
                struct req_op_context opctx = {0};
                fsal_status_t st;

                SECNFS_D("Closing hdl = %x; writing header (filesize: %u)",
                         hdl, get_filesize(hdl));

                st = write_header(obj_hdl, &opctx);

                if (FSAL_IS_ERROR(st)) {
                        /* when unlink a pinned file, fsal_close will not be
                         * called. But cache_inode_lru_clean() will eventually
                         * call this fsal_close, resulting in write_header
                         * to a nonexistent remote handle.
                         */
                        if (st.major == ERR_FSAL_STALE) {
                                SECNFS_D("stale remote handle(maybe unlinked)");
                        } else {
                                SECNFS_D("write_header failed: %d", st.major);
                                return st;
                        }
                }
        }

        return next_ops.obj_ops->close(next_handle(obj_hdl));
}


/* secnfs_lru_cleanup
 * free non-essential resources at the request of cache inode's
 * LRU processing identifying this handle as stale enough for resource
 * trimming.
 */
fsal_status_t secnfs_lru_cleanup(struct fsal_obj_handle *obj_hdl,
                                 lru_actions_t requests)
{
        return next_ops.obj_ops->lru_cleanup(next_handle(obj_hdl), requests);
}
