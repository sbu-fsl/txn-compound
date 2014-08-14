/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) Stony Brook University 2014
 * by Ming Chen <v.mingchen@gmail.com>
 */

/**
 * @file    nfs_dix.h
 * @brief   Data Integrity eXtensions (DIX) routines
 *
 */

#ifndef _NFS_DIX_H
#define _NFS_DIX_H

struct sd_dif_tuple {
       uint16_t guard_tag;      /* Checksum */
       uint16_t app_tag;        /* Opaque storage */
       uint32_t ref_tag;        /* Target LBA or indirect LBA */
};

#define GENERATE_GUARD	(1)
#define GENERATE_REF	(2)
#define GENERATE_APP	(4)
#define GENERATE_ALL	(7)

#define PI_INTERVAL_SIZE 4096
#define PI_INTERVAL_SHIFT 12
#define PI_SD_DIF_SIZE (PI_INTERVAL_SIZE >> 9) * 8  /* for each PI_INTERVAL */

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

static inline bool is_pi_aligned(uint64_t data_len)
{
        return (data_len & (PI_INTERVAL_SIZE - 1)) == 0;
}

static inline uint64_t get_pi_count(uint64_t data_len)
{
        return (data_len + PI_INTERVAL_SIZE - 1) >> PI_INTERVAL_SHIFT;
}

static inline uint64_t get_pi_size(uint64_t data_len)
{
        return get_pi_count(data_len) * PI_SD_DIF_SIZE;
}

#endif				/* _NFS_DIX_H */
