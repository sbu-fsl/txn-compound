/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @file  secnfs.h
 * @brief Encrypt and decrypt data
 */

#ifndef H_SECNFS
#define H_SECNFS

#include <stdint.h>
#include <stdlib.h>
#include <sys/param.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SECNFS_KEY_LENGTH 16

typedef struct { uint8_t bytes[SECNFS_KEY_LENGTH + 1]; } secnfs_key_t;

/**
 * Status codes of SECNFS.
 */
typedef enum {
        SECNFS_OKAY = 0,
        SECNFS_CRYPTO_ERROR = 1,
        SECNFS_WRONG_CONFIG,
} secnfs_s;


/**
 * SECNFS context.
 */
typedef struct {
        uint32_t context_size;          /*!< size of context */
        void *context;                  /*!< context data */
        char context_cache_file[MAXPATHLEN + 1];
        char secnfs_name[MAXPATHLEN + 1];       /*!< secnfs unique name */
        unsigned create_if_no_context : 1;
} secnfs_info_t;


/*
 * @brief Increase the counter.
 */
secnfs_key_t *incr_ctr(secnfs_key_t *iv, unsigned size, int incr);

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
 * @brief Create SECNFS context.
 *
 * @param[out] context  SECNFS context.
 *
 * The caller should use secnfs_destroy_context to free the returned context.
 *
 * @return SECNFS_OKAY on success.
 */
secnfs_s secnfs_create_context(secnfs_info_t *info);


/**
 * @brief Destroy SECNFS context.
 *
 * @param[in]  context   SECNFS context.
 */
void secnfs_destroy_context(secnfs_info_t *info);


/**
 * @brief Create new key file.
 *
 * @param[in]   context SECNFS Context
 * @param[out]  fek     File Encryption Key
 * @param[out]  iv      Initialization vector
 * @param[out]  keyfile KeyFile data
 * @param[out]  kf_len  Length of KeyFile data
 *
 * The caller is the owner of all returned data and should free them properly.
 *
 * @return SECNFS_OKAY on success.
 */
secnfs_s secnfs_create_keyfile(secnfs_info_t *info,
                               secnfs_key_t **fek,
                               secnfs_key_t **iv,
                               void **keyfile,
                               int *kf_len);


#ifdef __cplusplus
}
#endif

#endif
