/**
 * @file  ctr_crypto.h
 * @brief Encrypt and decrypt data
 */
#include "fsal.h"

/** Logarithm (base 2) of block size */
#define BLOCK_SIZE_LOG2		6

/** Block size in bytes */
#define BLOCK_SIZE_BYTES	(1UL << BLOCK_SIZE_LOG2)

/**
 * Error codes of encryption and decryption
 */
enum {
	CRYPTFS_CRYPTO_NO_ERR = 0,
	CRYPTFS_CRYPTO_ERROR = 1
};

/**
 * @brief Encrypt buffer contents
 *
 * @param[in]      offset      Offset of data in file
 * @param[in]      buffer_size Size of buffer content
 * @param[in, out] buffer      Buffer containing plaintext. Output ciphertext.
 *
 * @return FSAL status
 */
fsal_status_t cryptfs_encrypt(uint64_t offset, size_t buffer_size, void *buffer);

/**
 * @brief Decrypt buffer contents
 *
 * @param[in]      offset      Offset of data in file
 * @param[in]      buffer_size Size of buffer content
 * @param[in, out] buffer      Buffer containing ciphertext. Output plaintext.
 *
 * @return FSAL status
 */
fsal_status_t cryptfs_decrypt(uint64_t offset, size_t buffer_size, void *buffer);

