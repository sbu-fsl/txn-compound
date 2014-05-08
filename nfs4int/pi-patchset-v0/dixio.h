/*
 * I/O library based on dix.
 *
 * by Ming Chen <v.mingchen@gmail.com>
 *
 */

#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define IOCB_CMD_PREADV		(7)
#define IOCB_CMD_PWRITEV	(8)
#define IOCB_CMD_PREADVM	(9)
#define IOCB_CMD_PWRITEVM	(10)

#define GENERATE_GUARD	(1)
#define GENERATE_REF	(2)
#define GENERATE_APP	(4)
#define GENERATE_ALL	(7)

struct sd_dif_tuple {
       uint16_t guard_tag;	/* Checksum */
       uint16_t app_tag;		/* Opaque storage */
       uint32_t ref_tag;		/* Target LBA or indirect LBA */
};

ssize_t do_dixio(int fd, off_t offset, int iocmd,
                 const struct iovec *iov, int iovcnt);

ssize_t dixio_pread(int fd, void *buf, void *prot_buf,
                    size_t count, off_t offset);

ssize_t dixio_pwrite(int fd, const void *buf, const void *prot_buf,
                     size_t count, off_t offset);
