/* vim:noexpandtab:shiftwidth=8:tabstop=8: */

#include "dixio.h"
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <libaio.h>
#include <sys/types.h>

#include "log.h"
#include "abstract_mem.h"

#define GENERATE_GUARD	(1)
#define GENERATE_REF	(2)
#define GENERATE_APP	(4)
#define GENERATE_ALL	(7)

#define MAX_AIO_EVENTS 2

#define PAGESIZE 4096
#define PAGESHIFT 12

/* Stuff that should go in libaio.h */
#define IO_EXT_INVALID	(0)
#define	IO_EXT_PI	(1)	/* protection info attached */

#define IOCB_FLAG_EXTENSIONS	(1 << 1)

#include <linux/fs.h>	/* get __u64, __u32 */
struct io_extension {
	__u64 ie_size;
	__u64 ie_has;

	/* PI stuff */
	__u64 ie_pi_buf;
	__u32 ie_pi_buflen;
	__u32 ie_pi_ret;
	__u32 ie_pi_flags;
};

static void io_prep_extensions(struct iocb *iocb, struct io_extension *ext,
			       unsigned int nr)
{
	iocb->u.c.flags |= IOCB_FLAG_EXTENSIONS;
	iocb->u.c.__pad3 = (long long)ext;
}

static void io_prep_extension(struct io_extension *ext)
{
	memset(ext, 0, sizeof(struct io_extension));
	ext->ie_size = sizeof(*ext);
}

static void io_prep_extension_pi(struct io_extension *ext, void *buf,
				 unsigned int buflen, unsigned int flags)
{
	ext->ie_has |= IO_EXT_PI;
	ext->ie_pi_buf = (__u64)buf;
	ext->ie_pi_buflen = buflen;
	ext->ie_pi_flags = flags;
}
/* End stuff for libaio.h */

#define READ	0
#define WRITE	1

#ifdef COMPONENT_FSAL
#define DIX_ERR(msg, args...) LogError(COMPONENT_FSAL, msg, ##args)
#else
#define DIX_ERR(msg, args...) perror(msg)
#endif

static inline size_t page_roundup(size_t size) {
	return ((size + PAGESIZE - 1) >> PAGESHIFT) << PAGESHIFT;
}

static inline int page_aligned(void *buf) {
	return !((unsigned long)buf & (PAGESIZE - 1));
}

static ssize_t __do_dixio(int fd, void *buf, void *pbuf, size_t count,
			  off_t offset, int rw)
{
	int ret;
	struct iovec iov[1];
	struct iocb cb = {0};
	struct iocb *iocbps[1] = {&cb};
	struct io_event events[1];
	struct io_extension iocb_ext[1];
	io_context_t ioctx;

	assert(page_aligned(buf));
	assert(page_aligned(pbuf));
	assert(page_aligned((void *)count));
	assert(page_aligned((void *)offset));
	assert(rw == READ || rw == WRITE);

	if (io_queue_init(MAX_AIO_EVENTS, &ioctx)) {
		DIX_ERR("io_queue_init");
		errno = EIO;
		return -1;
	}

	iov[0].iov_base = buf;
	iov[0].iov_len = count;
	if (rw == WRITE)
		io_prep_pwritev(&cb, fd, iov, 1, offset);
	else
		io_prep_preadv(&cb, fd, iov, 1, offset);

	if (pbuf) {
		io_prep_extension(iocb_ext);
		io_prep_extension_pi(iocb_ext, pbuf, get_pi_size(count),
				     rw == WRITE ? GENERATE_GUARD : 0);
		io_prep_extensions(&cb, iocb_ext, 1);
	}

	ret = io_submit(ioctx, 1, iocbps);
	if (ret < 0) {
		DIX_ERR("io_submit");
		return ret;
	}

	ret = io_getevents(ioctx, 1, 1, events, NULL);
	if (ret < 0) {
		DIX_ERR("io_getevents");
		return ret;
	}

	if ((ret = (signed)events[0].res) < 0) {
		errno = -ret;
		fprintf(stderr, "do_dixio(%d) failed: %d %s\n", rw, errno, strerror(errno));
		return ret;
	}

	if (io_queue_release(ioctx))
		fprintf(stderr, "io_queue_release failed\n");

	return ret;
}


static ssize_t do_dixio(int fd, void *buf, void *prot_buf, size_t count,
			off_t offset, int rw)
{
	void *pbuf = prot_buf;
	void *buf_align = buf;
	ssize_t ret = 0;
	size_t pi_size = 0;

	if (prot_buf && !page_aligned(prot_buf)) {
		pi_size = get_pi_size(count);
		// fprintf(stderr, "pbuf %x not aligned\n", prot_buf);
		pbuf = gsh_malloc_aligned(PAGESIZE, pi_size);
		if (!pbuf) {
			DIX_ERR("could not alloc memory for prot_buf");
			errno = ENOMEM;
			return -1;
		}
		if (rw == WRITE)
			memcpy(pbuf, prot_buf, pi_size);
	}

	if (!page_aligned(buf)) {
		// fprintf(stderr, "buf %x not aligned\n", buf);
		buf_align = gsh_malloc_aligned(PAGESIZE, count);
		if (!buf_align) {
			DIX_ERR("could not alloc memory for buf");
			errno = ENOMEM;
			return -1;
		}
		if (rw == WRITE)
			memcpy(buf_align, buf, count);
	}

	// fprintf(stderr, "DIX %s %u (%u), %x, %x\n", rw == READ ? "READ" : "WRITE",
	// 	offset, count, buf_align, pbuf);

	ret = __do_dixio(fd, buf_align, pbuf, count, offset, rw);

	if (prot_buf && !page_aligned(prot_buf)) {
		if (ret > 0 && (rw == READ)) {
			/* should not happen if called by nfs4_op_read_plus()
			 * can happen from other caller (dixio_test.c) */
			fprintf(stderr, "READ pbuf %x not aligned\n", prot_buf);
			memcpy(prot_buf, pbuf, pi_size);
		}

		gsh_free(pbuf);
	}

	if (!page_aligned(buf)) {
		if (ret > 0 && (rw == READ)) {
			/* should not happen if called by nfs4_op_read_plus()
			 * can happen from other caller (dixio_test.c) */
			fprintf(stderr, "READ buf %x not aligned\n", prot_buf);
			memcpy(buf, buf_align, count);
		}

		gsh_free(buf_align);
	}

	return ret;
}


ssize_t dixio_pread(int fd, void *buf, void *prot_buf,
                    size_t count, off_t offset)
{
	return do_dixio(fd, buf, prot_buf, count, offset, READ);
}


ssize_t dixio_pwrite(int fd, const void *buf, const void *prot_buf,
                     size_t count, off_t offset)
{
	return do_dixio(fd, (void *)buf, (void *)prot_buf, count, offset,
			WRITE);
}
