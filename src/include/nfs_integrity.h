/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * by Ming Chen <v.mingchen@gmail.com>
 */

/**
 * @file    nfs_integrity.h
 * @brief   NFS end-to-end integrity routines
 *
 */

#ifndef _NFS_INTEGRITY_H
#define _NFS_INTEGRITY_H

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

static inline uint64_t get_pi_count(uint64_t dlen) {
        return (dlen + PI_INTERVAL_SIZE - 1) >> PI_INTERVAL_SHIFT;
}

static inline uint64_t get_pi_size(uint64_t dlen) {
        /* +1 for the header */
        return (get_pi_count(dlen) + 1) * sizeof(sd_dif_tuple);
}


#endif				/* _NFS_INTEGRITY_H */
