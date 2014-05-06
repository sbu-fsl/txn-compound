/*
 * I/O library based on dix.
 *
 * by Ming Chen <v.mingchen@gmail.com>
 *
 */

#include <unistd.h>

ssize_t dixio_pread(int fd, void *buf, void *prot_buf,
                    size_t count, off_t offset);

ssize_t dixio_pwrite(int fd, const void *buf, const void *prot_buf,
                     size_t count, off_t offset);
