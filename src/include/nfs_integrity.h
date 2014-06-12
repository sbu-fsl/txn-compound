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
       uint16_t guard_tag;      /* Checksum */
       uint16_t app_tag;        /* Opaque storage */
       uint32_t ref_tag;        /* Target LBA or indirect LBA */
};

#define PI_INTERVAL_SIZE 4096
#define PI_INTERVAL_SHIFT 12
#define PI_DIF_HEADER_SIZE 8    /* same size as struct sd_dif_tuple */
#define PI_SD_DIF_SIZE (PI_INTERVAL_SIZE >> 9) * 8  /* for each PI_INTERVAL */

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

/**
 * Fill sd_dif buffer that comprises a sequence of sd_dif_tuple (8 bytes).
 * For each tuple, only fill the last 6 bytes (application & reference tag).
 *
 * @param[out]  dif_buf         sd_dif buffer to be filled
 * @param[in]   obj_buf         buffer containing object(s)
 * @param[in]   obj_size        size of one object, should be multiple of 48
 * @param[in]   num             number of objects
 *
 * dif_buf should be large enough to contain obj_buf (obj_size * num) as well
 * as intact guard tags (2 bytes for each sd_dif_tuple).
 */
static inline void fill_sd_dif(uint8_t *dif_buf, uint8_t *obj_buf,
                               size_t obj_size, size_t num)
{
        int i;
        assert(obj_size % 48 == 0);
        for (i = 0; i < obj_size * num / 6; i++)
                memcpy(dif_buf + i * 8 + 2, obj_buf + i * 6, 6);
}

/**
 * Extract content from sd_dif buffer to obj_buf.
 * For each sd_dif_tuple in sd_dif buffer, extract the last 6 bytes
 * (application & reference tag) and concatenate them into obj_buf.
 *
 * @param[in]   dif_buf         sd_dif buffer to be filled
 * @param[out]  obj_buf         buffer containing object(s)
 * @param[in]   obj_size        size of one object, should be multiple of 48
 * @param[in]   num             number of objects
 *
 * obj_buf should be at least obj_size * num large.
 */
static inline void extract_from_sd_dif(uint8_t *dif_buf, uint8_t *obj_buf,
                                       size_t obj_size, size_t num)
{
        int i;
        assert(obj_size % 48 == 0);
        for (i = 0; i < obj_size * num / 6; i++)
                memcpy(obj_buf + i * 6, dif_buf + i * 8 + 2, 6);
}

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

static inline bool is_pi_aligned(uint64_t data_len) {
        return (data_len & (PI_INTERVAL_SIZE - 1)) == 0;
}

static inline uint64_t get_pi_count(uint64_t data_len) {
        return (data_len + PI_INTERVAL_SIZE - 1) >> PI_INTERVAL_SHIFT;
}

static inline uint64_t get_pi_size(uint64_t data_len) {
        /* include DIF header (user flags such as GENERATE_ALL) */
        return get_pi_count(data_len) * PI_SD_DIF_SIZE + PI_DIF_HEADER_SIZE;
}

#endif				/* _NFS_INTEGRITY_H */
