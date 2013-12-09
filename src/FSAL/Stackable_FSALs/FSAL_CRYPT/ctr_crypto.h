/**
 * @file  ctr_crypto.h
 * @brief Encrypt and decrypt data
 */
#include "fsal.h"

#define BLOCK_SIZE_LOG2		6
#define BLOCK_SIZE_BYTES	(1UL << BLOCK_SIZE_LOG2)

enum {
	CRYPTFS_CRYPTO_NO_ERR = 0,
	CRYPTFS_CRYPTO_ERROR = 1
};

fsal_status_t cryptfs_encrypt(uint64_t offset, size_t buffer_size, void *buffer);

fsal_status_t cryptfs_decrypt(uint64_t offset, size_t buffer_size, void *buffer);

