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

static bool should_read_keyfile(const struct secnfs_fsal_obj_handle *hdl)
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

        if (!FSAL_IS_ERROR(st) && should_read_keyfile(hdl)) {
                // read file key and iv
                st = read_keyfile(obj_hdl, opctx);
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
        uint64_t next_offset;
        struct data_plus data_plus;
        struct secnfs_dif secnfs_dif;
        uint8_t *secnfs_dif_buf = NULL;
        void *pi_buf = NULL;
        size_t pi_size;
        int i;

        SECNFS_D("hdl = %x; offset = %u, buffer_size = %u",
                 hdl, offset, buffer_size);

        next_offset = obj_hdl->type == REGULAR_FILE
                        ? offset + KEY_FILE_SIZE
                        : offset;

        /* To use read_plus, a struct data_plus need be prepared. */
        pi_size = get_pi_size(buffer_size);
        pi_buf = gsh_malloc(pi_size);
        if (pi_buf == NULL) {
                st = fsalstat(ERR_FSAL_NOMEM, 0);
                goto out;
        }
        data_plus_type_protected_data_init(&data_plus, next_offset,
                                           pi_size, pi_buf,
                                           buffer_size, buffer);

        st = next_ops.obj_ops->read_plus(hdl->next_handle,
                                         opctx,
                                         next_offset, buffer_size,
                                         buffer, read_amount,
                                         &data_plus,
                                         end_of_file);
        if (FSAL_IS_ERROR(st))
                goto out;

        SECNFS_D("hdl = %x; read_amount = %u", hdl, *read_amount);
        /* TODO pd_info_len may not equal pi_size due to partial read */
        SECNFS_D("hdl = %x; pd_info_len = %u", hdl,
                        data_plus.u.pdata.pd_info.pd_info_len);
        dump_pi_buf(pi_buf, pi_size);

        if (obj_hdl->type == REGULAR_FILE) {
                assert(hdl->key_initialized);
                /* TODO only decrypt "*read_amount" */
                /*
                secnfs_s ret = secnfs_decrypt(hdl->fk, hdl->iv, offset,
                                              buffer_size, buffer, buffer);
                */

                secnfs_dif_buf = gsh_malloc(PI_SECNFS_DIF_SIZE);
                if (pi_buf == NULL) {
                        st = fsalstat(ERR_FSAL_NOMEM, 0);
                        goto out;
                }

                for (i = 0; i < get_pi_count(buffer_size); i++) {
                        extract_from_sd_dif(pi_buf + PI_DIF_HEADER_SIZE
                                        + i * PI_SD_DIF_SIZE, secnfs_dif_buf,
                                        PI_SECNFS_DIF_SIZE, 1);
                        secnfs_dif_from_buf(&secnfs_dif, secnfs_dif_buf);
                        SECNFS_D("hdl = %x; ver(%u) = %llx",
                                 hdl, i + (offset >> PI_INTERVAL_SHIFT),
                                 secnfs_dif.version);
                        SECNFS_D("hdl = %x; tag(%u) = %02x...%02x",
                                 hdl, i + (offset >> PI_INTERVAL_SHIFT),
                                 secnfs_dif.tag[0], secnfs_dif.tag[15]);

                        secnfs_s ret = secnfs_verify_decrypt(
                                        hdl->fk,
                                        hdl->iv,
                                        offset + i * PI_INTERVAL_SIZE,
                                        PI_INTERVAL_SIZE,
                                        buffer + i * PI_INTERVAL_SIZE,
                                        VERSION_SIZE,
                                        &(secnfs_dif.version),
                                        secnfs_dif.tag,
                                        buffer + i * PI_INTERVAL_SIZE);

                        if (ret != SECNFS_OKAY) {
                                SECNFS_D("hdl = %x; ret(%u) = %d", hdl, i, ret);
                                st = secnfs_to_fsal_status(ret);
                                goto out;
                        }
                }
                st = secnfs_to_fsal_status(SECNFS_OKAY);
        }

out:
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
        uint64_t next_offset = offset;
        struct data_plus data_plus;
        uint8_t *pd_buf = NULL;
        uint8_t *pi_buf = NULL;
        size_t pi_size;
        struct secnfs_dif secnfs_dif = {0};
        uint8_t *secnfs_dif_buf = NULL;
        fsal_status_t st;
        int i;

        SECNFS_D("hdl = %x; write to %u (%u)\n", hdl, offset, buffer_size);
        if (obj_hdl->type == REGULAR_FILE) {
                next_offset += KEY_FILE_SIZE;
                SECNFS_D("hdl = %x; key = %d\n", hdl, hdl->key_initialized);
                assert(hdl->key_initialized);
                /*
                secnfs_s ret = secnfs_encrypt(hdl->fk,
                                              hdl->iv,
                                              offset,
                                              buffer_size,
                                              buffer,
                                              buffer);
                */

                /* alloc memory for ciphertext & protection info (DIF) */
                pd_buf = gsh_malloc(buffer_size + TAG_SIZE);
                if (pd_buf == NULL) {
                        st = fsalstat(ERR_FSAL_NOMEM, 0);
                        goto out;
                }

                pi_size = get_pi_size(buffer_size);
                pi_buf = gsh_malloc(pi_size);
                SECNFS_D("hdl = %x; pi_size = %u\n", hdl, pi_size);
                if (pi_buf == NULL) {
                        st = fsalstat(ERR_FSAL_NOMEM, 0);
                        goto out;
                }
                memset(pi_buf, 0, PI_DIF_HEADER_SIZE);
                pi_buf[0] = GENERATE_GUARD; /* required DIF header */

                secnfs_dif_buf = gsh_malloc(PI_SECNFS_DIF_SIZE);
                if (pi_buf == NULL) {
                        st = fsalstat(ERR_FSAL_NOMEM, 0);
                        goto out;
                }

                secnfs_dif.version = 0x1234567890abcdef;
                /* XXX assume plaintext is aligned currently */
                for (i = 0; i < get_pi_count(buffer_size); i++) {
                        secnfs_s ret = secnfs_auth_encrypt(
                                                hdl->fk,
                                                hdl->iv,
                                                offset + i * PI_INTERVAL_SIZE,
                                                PI_INTERVAL_SIZE,
                                                buffer + i * PI_INTERVAL_SIZE,
                                                VERSION_SIZE,
                                                &secnfs_dif.version,
                                                pd_buf + i * PI_INTERVAL_SIZE,
                                                secnfs_dif.tag);

                        if (ret != SECNFS_OKAY) {
                                st = secnfs_to_fsal_status(ret);
                                goto out;
                        }

                        SECNFS_D("hdl = %x; ver(%u) = %llx",
                                 hdl, i + (offset >> PI_INTERVAL_SHIFT),
                                 secnfs_dif.version);
                        SECNFS_D("hdl = %x; tag(%u) = %02x...%02x",
                                 hdl, i + (offset >> PI_INTERVAL_SHIFT),
                                 secnfs_dif.tag[0], secnfs_dif.tag[15]);

                        secnfs_dif_to_buf(&secnfs_dif, secnfs_dif_buf);
                        fill_sd_dif(pi_buf + PI_DIF_HEADER_SIZE
                                        + i * PI_SD_DIF_SIZE, secnfs_dif_buf,
                                        PI_SECNFS_DIF_SIZE, 1);
                }
                dump_pi_buf(pi_buf, pi_size);
        }

        /* prepare data_plus for write_plus */
        /* XXX assume regular file */
        data_plus_type_protected_data_init(&data_plus, next_offset,
                                           pi_size, pi_buf,
                                           buffer_size, pd_buf);

        st = next_ops.obj_ops->write_plus(next_handle(obj_hdl),
                                          opctx,
                                          next_offset, buffer_size,
                                          buffer, write_amount,
                                          &data_plus,
                                          fsal_stable);
out:
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
