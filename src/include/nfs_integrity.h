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

struct sd_dif_tuple {
       uint16_t guard_tag;	/* Checksum */
       uint16_t app_tag;		/* Opaque storage */
       uint32_t ref_tag;		/* Target LBA or indirect LBA */
};

#define PI_INTERVAL_SIZE 4096
#define PI_INTERVAL_SHIFT 12

#define GENERATE_GUARD	(1)
#define GENERATE_REF	(2)
#define GENERATE_APP	(4)
#define GENERATE_ALL	(7)

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

static inline bool is_pi_aligned(uint64_t data_len) {
        return (data_len & (PI_INTERVAL_SIZE - 1)) == 0;
}

static inline uint64_t get_pi_count(uint64_t data_len) {
        return (data_len + PI_INTERVAL_SIZE - 1) >> PI_INTERVAL_SHIFT;
}

static inline uint64_t get_pi_size(uint64_t data_len) {
        /* +1 for the header (user flags such as GENERATE_ALL) */
        return (get_pi_count(data_len) + 1) * sizeof(struct sd_dif_tuple);
}


#endif				/* _NFS_INTEGRITY_H */
