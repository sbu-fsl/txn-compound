#include "dixio.h"
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <libaio.h>
#include <sys/types.h>

#define GENERATE_GUARD	(1)
#define GENERATE_REF	(2)
#define GENERATE_APP	(4)
#define GENERATE_ALL	(7)

#define NR_IOS	(1)

#define MAX_AIO_EVENTS 2

/* 8 bytes protection information. */
#define PROT_INFO_SIZE 8

#define PAGESIZE 4096

static inline int page_aligned(void *buf) {
	return !((unsigned long)buf & (PAGESIZE - 1));
}

ssize_t do_dixio(int fd, off_t offset, int iocmd,
		 const struct iovec *iov, int iovcnt)
{
	int ret;
	struct iocb cb = {0};
	struct iocb *iocbps[1] = {&cb};
	struct io_event events[1];
	io_context_t ioctx;

	if (io_queue_init(MAX_AIO_EVENTS, &ioctx)) {
		perror("io_queue_init");
		return -EIO;
	}

	cb.aio_fildes = fd;
	cb.aio_lio_opcode = iocmd;
	cb.aio_reqprio = 0;
	cb.u.c.buf = (void *)iov;
	cb.u.c.nbytes = iovcnt;
	cb.u.c.offset = offset;

	ret = io_submit(ioctx, 1, iocbps);
	if (ret < 0) {
		perror("io_submit");
		return ret;
	}

	ret = io_getevents(ioctx, 1, 1, events, NULL);
	if (ret < 0) {
		perror("io_getevents");
		return ret;
	}

	if ((ret = (signed)events[0].res) < 0) {
		fprintf(stderr, "do_dixio %d failed\n", iocmd);
		return ret;
	}

	io_queue_release(ioctx);

	return ret;
}


static void setup_iov(struct iovec *iov, void *buf, void *prot_buf,
		      size_t count, off_t offset)
{
	assert(page_aligned(buf));
	assert(page_aligned(prot_buf));
	assert(page_aligned((void *)count));
	assert(page_aligned((void *)offset));

	iov[0].iov_base = buf;
	iov[0].iov_len = count;
	iov[1].iov_base = prot_buf;
	iov[1].iov_len = ((count >> 9) + 1) * PROT_INFO_SIZE;
}


ssize_t dixio_pread(int fd, void *buf, void *prot_buf,
                    size_t count, off_t offset)
{
	struct iovec iov[2];
	int iovcnt = prot_buf ? 2 : 1;
	int iocmd = prot_buf ? IOCB_CMD_PREADVM : IOCB_CMD_PREADV;

	setup_iov(iov, buf, prot_buf, count, offset);
	return do_dixio(fd, offset, iocmd, iov, iovcnt);
}


ssize_t dixio_pwrite(int fd, const void *buf, const void *prot_buf,
                     size_t count, off_t offset)
{
	struct iovec iov[2];
	int iovcnt = prot_buf ? 2 : 1;
	int iocmd = prot_buf ? IOCB_CMD_PWRITEVM : IOCB_CMD_PWRITEV;

	setup_iov(iov, (void *)buf, (void *)prot_buf, count, offset);
	return do_dixio(fd, offset, iocmd, iov, iovcnt);
}
