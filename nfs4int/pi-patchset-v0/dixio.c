#define _GNU_SOURCE

#include "dixio.h"
#include <libaio.h>

#define IOCB_CMD_PREADVM	(9)
#define IOCB_CMD_PWRITEVM	(10)
#define GENERATE_GUARD	(1)
#define GENERATE_REF	(2)
#define GENERATE_APP	(4)
#define GENERATE_ALL	(7)

#define NR_IOS	(1)

#define MAX_AIO_EVENTS 2

/* 8 bytes protection information. */
#define PROT_INFO_SIZE 8

static inline bool page_aligned(void *buf) { return !(buf & (PAGESIZE - 1)); }

static ssize_t do_dixio(int fd, int iocb_cmd, void *buf, void *prot_buf,
                        size_t count, off_t offset)
{
	int ret;
	struct iovec iov[2];
	struct iocb iocbs[NR_IOS];
	struct iocb *iocbps[NR_IOS];
	struct io_event events[NR_IOS];
	io_context_t ioctx;

	if (io_queue_init(MAX_AIO_EVENTS, &ioctx)) {
		perror("io_queue_init");
		return -EIO;
	}

	assert(page_aligned(buf));
	assert(page_aligned(prot_buf));
	assert(page_aligned((void *)count));
	assert(page_aligned((void *)offset));

	iov[0].iov_base = buf;
	iov[0].iov_len = count;
	iov[1].iov_base = prot_buf;
	iov[1].iov_len = ((count >> 9) + 1) * PROT_INFO_SIZE;

	iocbps[0] = iocbs;
	if (iocb_cmd == IOCB_CMD_PREADVM) {
		io_prep_preadv(iocbs, fd, iov, 2, offset);
	} else {
		assert(iocb_cmd == IOCB_CMD_PWRITEVM);
		io_prep_pwritev(iocbs, fd, iov, 2, offset);
	}
	iocbs[0].aio_lio_opcode = iocb_cmd;

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
		perror("io_pwritev");
		return ret;
	}

	return ret;
}


ssize_t dixio_pread(int fd, void *buf, void *prot_buf,
                    size_t count, off_t offset)
{
	return do_dixio(fd, IOCB_CMD_PREADVM, buf, prot_buf, count, offset);
}


ssize_t dixio_pwrite(int fd, const void *buf, const void *prot_buf,
                     size_t count, off_t offset)
{
	return do_dixio(fd, IOCB_CMD_PWRITEVM,
			(void *)buf, (void *)prot_buf, count, offset);
}
