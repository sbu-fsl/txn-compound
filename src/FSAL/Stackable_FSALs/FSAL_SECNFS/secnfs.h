/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @file  secnfs.h
 * @brief Encrypt and decrypt data
 */

#ifndef H_SECNFS
#define H_SECNFS

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SECNFS_KEY_LENGTH 16

typedef struct { uint8_t bytes[SECNFS_KEY_LENGTH]; } secnfs_key_t;

/**
 * Status codes of SECNFS.
 */
typedef enum {
        SECNFS_OKAY = 0,
        SECNFS_CRYPTO_ERROR = 1,
} secnfs_s;


/*
 * @brief Increase the counter.
 */
inline secnfs_key_t *incr_ctr(secnfs_key_t *iv, unsigned size, int incr) {
        uint8_t *ctr = iv->bytes;
        int i = size - 1;
        int carry = incr;

	for (; carry && i >= 0; --i) {
		carry += ctr[i];
		ctr[i] = carry & 0xFF;
		carry >>= 8;
	}

	return iv;
}


/**
 * @brief Encrypt buffer contents
 *
 * @param[in]   key     Encryption key
 * @param[in]   iv      Initialization vector
 * @param[in]   offset  Offset of data in file
 * @param[in]   size    Size of buffer, also the amount of data to encrypt
 * @param[in]   plain   Buffer containing plaintext
 * @param[out]  buffer  Output buffer for ciphertext, can be the same as plain
 *
 * @return 0 on success.
 */
secnfs_s secnfs_encrypt(secnfs_key_t key,
                        secnfs_key_t iv,
                        uint64_t offset,
                        uint64_t size,
                        void *plain,
                        void *buffer);

/**
 * @brief Decrypt buffer contents
 *
 * @param[in]   key      Decryption key
 * @param[in]   iv       Initialization vector
 * @param[in]   offset   Offset of data in file
 * @param[in]   size     Size of buffer, also the amount of data to decrypt
 * @param[in]   cipher   Buffer containing ciphertext
 * @param[out]  buffer   Output buffer for decrypted plaintext
 *
 * @return 0 on success.
 */
secnfs_s secnfs_decrypt(secnfs_key_t key,
                        secnfs_key_t iv,
                        uint64_t offset,
                        uint64_t size,
                        void *cipher,
                        void *buffer);


/**
 * SECNFS context.
 */
typedef struct {
        uint32_t size;      /*!< size of context */
        void *data;         /*!< context data */
} secnfs_context_t;


/**
 * @brief Create SECNFS context.
 *
 * @param[out] context  SECNFS context.
 *
 * The caller should use secnfs_destroy_context to free the returned context.
 *
 * @return SECNFS_OKAY on success.
 */
secnfs_s secnfs_create_context(secnfs_context_t *context);


/**
 * @brief Destroy SECNFS context.
 *
 * @param[in]  context   SECNFS context.
 */
void secnfs_destroy_context(secnfs_context_t *context);


/**
 * @brief Create new key file.
 *
 * @param[out]  fek     File Encryption Key
 * @param[out]  iv      Initialization vector
 * @param[out]  keyfile KeyFile data
 *
 * The caller is the owner of all returned data and should free them properly.
 *
 * @return SECNFS_OKAY on success.
 */
secnfs_s secnfs_create_keyfile(secnfs_key_t *fek,
                               secnfs_key_t *iv,
                               void *keyfile);


#ifdef __cplusplus
}
#endif

#endif
