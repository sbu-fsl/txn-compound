/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * I/O library based on dix.
 *
 * by Ming Chen <v.mingchen@gmail.com>
 *
 */

#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "nfs_integrity.h"

#define IOCB_CMD_PREADV		(7)
#define IOCB_CMD_PWRITEV	(8)
#define IOCB_CMD_PREADVM	(9)
#define IOCB_CMD_PWRITEVM	(10)

ssize_t do_dixio(int fd, off_t offset, int iocmd,
                 const struct iovec *iov, int iovcnt);

ssize_t dixio_pread(int fd, void *buf, void *prot_buf,
                    size_t count, off_t offset);

ssize_t dixio_pwrite(int fd, const void *buf, const void *prot_buf,
                     size_t count, off_t offset);
