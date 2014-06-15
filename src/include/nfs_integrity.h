/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) Stony Brook University 2014
 * by Ming Chen <v.mingchen@gmail.com>
 */

/**
 * @file    nfs_integrity.h
 * @brief   NFS end-to-end integrity routines
 *
 */

#ifndef _NFS_INTEGRITY_H
#define _NFS_INTEGRITY_H

#include "nfsv41.h"
#include "nfs_dix.h"

struct data_plus {
        data_content4 content_type;
        union {
                data4 data;
                data_info4 hole;
                app_data_hole4 adh;
                data_protected4 pdata;
                data_protect_info4 pinfo;
        } u;
};

static inline void data_plus_to_read_plus_content(struct data_plus *dp,
                                                  read_plus_content4 *rpc4) {
        rpc4->rpc_content = dp->content_type;
        memcpy(&rpc4->read_plus_content4_u, &dp->u, sizeof(dp->u));
}

static inline void data_plus_from_read_plus_content(struct data_plus *dp,
                                                    read_plus_content4 *rpc4) {
        dp->content_type = rpc4->rpc_content;
        memcpy(&dp->u, &rpc4->read_plus_content4_u, sizeof(dp->u));
}

static inline void data_plus_to_write_plus_args(struct data_plus *dp,
                                                write_plus_arg4 *wpa4) {
        wpa4->wpa_content = dp->content_type;
        memcpy(&wpa4->write_plus_arg4_u, &dp->u, sizeof(dp->u));
}

static inline void data_plus_from_write_plus_args(struct data_plus *dp,
                                                  write_plus_arg4 *wpa4) {
        dp->content_type = wpa4->wpa_content;
        memcpy(&dp->u, &wpa4->write_plus_arg4_u, sizeof(dp->u));
}

static inline off_t data_plus_to_offset(struct data_plus *dp) {
        switch (dp->content_type) {
        case NFS4_CONTENT_DATA:
                return dp->u.data.d_offset;
        case NFS4_CONTENT_PROTECTED_DATA:
                return dp->u.pdata.pd_offset;
        case NFS4_CONTENT_PROTECT_INFO:
                return dp->u.pinfo.pi_offset;
        default:
                return 0;
        }
}

static inline size_t data_plus_to_pi_dlen(struct data_plus *dp) {
        assert(dp->content_type == NFS4_CONTENT_PROTECTED_DATA ||
               dp->content_type == NFS4_CONTENT_PROTECT_INFO);
        switch (dp->content_type) {
        case NFS4_CONTENT_PROTECTED_DATA:
                return dp->u.pdata.pd_info.pd_info_len;
        case NFS4_CONTENT_PROTECT_INFO:
                return dp->u.pinfo.pi_data.pi_data_len;
        default:
                return 0;
        }
}

static inline char* data_plus_to_pi_data(struct data_plus *dp) {
        assert(dp->content_type == NFS4_CONTENT_PROTECTED_DATA ||
               dp->content_type == NFS4_CONTENT_PROTECT_INFO);
        switch (dp->content_type) {
        case NFS4_CONTENT_PROTECTED_DATA:
                return dp->u.pdata.pd_info.pd_info_val;
        case NFS4_CONTENT_PROTECT_INFO:
                return dp->u.pinfo.pi_data.pi_data_val;
        default:
                return 0;
        }
}

static inline size_t data_plus_to_file_dlen(struct data_plus *dp) {
        assert(dp->content_type == NFS4_CONTENT_DATA ||
               dp->content_type == NFS4_CONTENT_PROTECTED_DATA);
        switch (dp->content_type) {
        case NFS4_CONTENT_DATA:
                return dp->u.data.d_data.d_data_len;
        case NFS4_CONTENT_PROTECTED_DATA:
                return dp->u.pdata.pd_data.pd_data_len;
        default:
                return 0;
        }
}

static inline char* data_plus_to_file_data(struct data_plus *dp) {
        assert(dp->content_type == NFS4_CONTENT_DATA ||
               dp->content_type == NFS4_CONTENT_PROTECTED_DATA);
        switch (dp->content_type) {
        case NFS4_CONTENT_DATA:
                return dp->u.data.d_data.d_data_val;
        case NFS4_CONTENT_PROTECTED_DATA:
                return dp->u.pdata.pd_data.pd_data_val;
        default:
                return 0;
        }
}

/* initialize data_plus whose content type is NFS4_CONTENT_PROTECTED_DATA */
static inline void data_plus_type_protected_data_init(struct data_plus *dp,
                                                      uint64_t offset,
                                                      size_t pi_size,
                                                      void *pi_buf,
                                                      size_t pd_size,
                                                      void *pd_buf) {

        dp->content_type = NFS4_CONTENT_PROTECTED_DATA;
        dp->u.pdata.pd_type.pi_type = NFS_PI_TYPE5;
        dp->u.pdata.pd_type.pi_other_data = 1;
        dp->u.pdata.pd_offset = offset;
        dp->u.pdata.pd_allocated = 1;
        dp->u.pdata.pd_info.pd_info_len = pi_size;
        dp->u.pdata.pd_info.pd_info_val = pi_buf;
        dp->u.pdata.pd_data.pd_data_len = pd_size;
        dp->u.pdata.pd_data.pd_data_val = pd_buf;
}

static inline void dump_pi_buf(uint8_t *pi_buf, size_t pi_size)
{
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

#endif				/* _NFS_INTEGRITY_H */
