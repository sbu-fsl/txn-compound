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

/* TODO move to include/nfs_integrity.h */
static inline void dump_pi_buf(uint8_t *pi_buf, size_t pi_size) {
        char *pi_hex, *curr;
        int i, hex_len;
        hex_len = pi_size * 2 + pi_size / 8;
        pi_hex = gsh_malloc(hex_len);
        for (i = 0, curr = pi_hex; i < pi_size; i++) {
                sprintf(curr, "%02x", *(pi_buf + i));
                curr += 2;
                if (i % 8 == 7) {
                        *curr = ' ';
                        curr += 1;
                }
        }
        *(curr-1) = '\0';
        LogDebug(COMPONENT_FSAL, "=secnfs=pi_buf: %s", pi_hex);
        gsh_free(pi_hex);
}

/* TODO move to include/nfs_integrity.h */
static inline void nfs_dif_to_sd_dif(struct nfs_dif *nfs_dif,
                                     uint8_t *pi_buf) {
        int i;
        uint8_t tmp_buf[PI_NFS_DIF_SIZE];

        /* serialize to a contiguous buf */
        for (i = 0; i < VERSION_SIZE; i++)
                tmp_buf[i] = (nfs_dif->version >> (i * 8)) & 0xff;
        memcpy(tmp_buf + VERSION_SIZE, nfs_dif->tag, TAG_SIZE);
        memcpy(tmp_buf + VERSION_SIZE + TAG_SIZE, nfs_dif->unused, 24);

        /* copy to noncontiguous sd_dif_buf chunks */
        for (i = 0; i < PI_NFS_DIF_SIZE / 6; i++)
                memcpy(pi_buf + i * 8 + 2, tmp_buf + i * 6, 6);
}

/* TODO move to include/nfs_integrity.h */
static inline void sd_dif_to_nfs_dif(uint8_t *pi_buf,
                                     struct nfs_dif *nfs_dif) {
        int i;
        uint8_t tmp_buf[PI_NFS_DIF_SIZE];

        /* sd_dif_buf chunks to a contiguous buf */
        for (i = 0; i < PI_NFS_DIF_SIZE / 6; i++)
                memcpy(tmp_buf + i * 6, pi_buf + i * 8 + 2, 6);

        /* deserialize to nfs_dif */
        nfs_dif->version = 0;
        for (i = VERSION_SIZE - 1; i >= 0; i--)
                nfs_dif->version = (nfs_dif->version << 8) | tmp_buf[i];
        memcpy(nfs_dif->tag, tmp_buf + VERSION_SIZE, TAG_SIZE);
        memcpy(nfs_dif->unused, tmp_buf + VERSION_SIZE + TAG_SIZE, 24);
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
        struct nfs_dif nfs_dif;
        void *pi_buf = NULL;
        size_t pi_size;
        int i;

        SECNFS_D("hdl = %x; offset = %u, buffer_size = %u",
                 hdl, offset, buffer_size);

        next_offset = obj_hdl->type == REGULAR_FILE
                        ? offset + KEY_FILE_SIZE
                        : offset;

        /* To use read_plus, a struct data_plus need be prepared. */
        memset(&data_plus, 0, sizeof(data_plus));
        pi_size = get_pi_size(buffer_size);
        pi_buf = gsh_malloc(pi_size);
        if (pi_buf == NULL) {
                st = fsalstat(ERR_FSAL_NOMEM, 0);
                goto out;
        }

        data_plus.content_type = NFS4_CONTENT_PROTECTED_DATA;
        data_plus.u.pdata.pd_type.pi_type = NFS_PI_TYPE5;
        data_plus.u.pdata.pd_type.pi_other_data = 1;
        data_plus.u.pdata.pd_offset = next_offset;
        data_plus.u.pdata.pd_allocated = 1;
        data_plus.u.pdata.pd_info.pd_info_val = pi_buf;
        data_plus.u.pdata.pd_data.pd_data_len = buffer_size;
        data_plus.u.pdata.pd_data.pd_data_val = buffer;

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
        SECNFS_D("hdl = %x; pd_offset = %u", hdl, data_plus.u.pdata.pd_offset);
        dump_pi_buf(pi_buf, pi_size);

        if (obj_hdl->type == REGULAR_FILE) {
                assert(hdl->key_initialized);
                /* TODO only decrypt "*read_amount" */
                /*
                secnfs_s ret = secnfs_decrypt(hdl->fk, hdl->iv, offset,
                                              buffer_size, buffer, buffer);
                */

                for (i = 0; i < get_pi_count(buffer_size); i++) {
                        sd_dif_to_nfs_dif(pi_buf + i * PI_SD_DIF_SIZE
                                          + PI_DIF_HEADER_SIZE, &nfs_dif);
                        SECNFS_D("hdl = %x; ver(%u) = %llx",
                                        hdl, i, nfs_dif.version);
                        SECNFS_D("hdl = %x; tag(%u) = %02x...%02x",
                                 hdl, i, nfs_dif.tag[0], nfs_dif.tag[15]);

                        secnfs_s ret = secnfs_verify_decrypt(
                                        hdl->fk,
                                        hdl->iv,
                                        offset + i * PI_INTERVAL_SIZE,
                                        PI_INTERVAL_SIZE,
                                        buffer + i * PI_INTERVAL_SIZE,
                                        VERSION_SIZE,
                                        &(nfs_dif.version),
                                        nfs_dif.tag,
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
        struct nfs_dif nfs_dif;
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
                memset(pi_buf, 0, pi_size);
                *pi_buf = GENERATE_GUARD; /* required DIF header */

                memset(nfs_dif.unused, 0, sizeof(nfs_dif.unused));
                nfs_dif.version = 0x1234567812345678;

                /* XXX assume plaintext is aligned currently */
                for (i = 0; i < get_pi_count(buffer_size); i++) {
                        secnfs_s ret = secnfs_auth_encrypt(
                                                hdl->fk,
                                                hdl->iv,
                                                offset + i * PI_INTERVAL_SIZE,
                                                PI_INTERVAL_SIZE,
                                                buffer + i * PI_INTERVAL_SIZE,
                                                VERSION_SIZE,
                                                &nfs_dif.version,
                                                pd_buf + i * PI_INTERVAL_SIZE,
                                                nfs_dif.tag);

                        if (ret != SECNFS_OKAY) {
                                st = secnfs_to_fsal_status(ret);
                                goto out;
                        }

                        SECNFS_D("hdl = %x; ver(%u) = %llx",
                                        hdl, i, nfs_dif.version);
                        SECNFS_D("hdl = %x; tag(%u) = %02x...%02x",
                                 hdl, i, nfs_dif.tag[0], nfs_dif.tag[15]);

                        nfs_dif_to_sd_dif(&nfs_dif,
                                pi_buf + PI_DIF_HEADER_SIZE + i * PI_SD_DIF_SIZE);
                }
                dump_pi_buf(pi_buf, pi_size);
        }

        /* prepare data_plus for write_plus */
        memset(&data_plus, 0, sizeof(data_plus));
        data_plus.content_type = NFS4_CONTENT_PROTECTED_DATA;
        data_plus.u.pdata.pd_type.pi_type = NFS_PI_TYPE5;
        data_plus.u.pdata.pd_type.pi_other_data = 1;
        data_plus.u.pdata.pd_offset = next_offset;
        data_plus.u.pdata.pd_allocated = 1;
        data_plus.u.pdata.pd_info.pd_info_len = pi_size;
        data_plus.u.pdata.pd_info.pd_info_val = pi_buf;
        data_plus.u.pdata.pd_data.pd_data_len = buffer_size;
        data_plus.u.pdata.pd_data.pd_data_val = pd_buf;

        st = next_ops.obj_ops->write_plus(next_handle(obj_hdl),
                                          opctx,
                                          next_offset, buffer_size,
                                          buffer, write_amount,
                                          &data_plus,
                                          fsal_stable);
out:
        gsh_free(pd_buf);
        gsh_free(pi_buf);

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
