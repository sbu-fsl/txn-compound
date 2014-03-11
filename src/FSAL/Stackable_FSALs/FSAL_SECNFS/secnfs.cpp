/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @file  secnfs.cpp
 * @brief Encrypt and decrypt data
 */

#include "secnfs.h"
#include <iostream>

#include <cryptopp/filters.h>
using CryptoPP::ArraySource;
using CryptoPP::ArraySink;
using CryptoPP::StreamTransformationFilter;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/ccm.h>
using CryptoPP::CTR_Mode;

#include <cryptopp/rsa.h>
using CryptoPP::RSA;

#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @brief Check if n is aligned by the encryption block size
 */
static int is_block_aligned(uint64_t n) { return !(n & (AES::BLOCKSIZE - 1)); }

static inline secnfs::Context *get_context(secnfs_context_t *secnfs_context) {
        return static_cast<secnfs::Context *>(secnfs_context->data);
}

secnfs_s secnfs_encrypt(secnfs_key_t key,
                        secnfs_key_t iv,
                        uint64_t offset,
                        uint64_t size,
                        void *plain,
                        void *buffer)
{
        assert(is_block_aligned(offset) && is_block_aligned(size));

        incr_ctr(&iv, SECNFS_KEY_LENGTH, offset / AES::BLOCKSIZE);

        try {
                CTR_Mode< AES >::Encryption e;
                e.SetKeyWithIV(key.bytes, AES::DEFAULT_KEYLENGTH, iv.bytes);

                ArraySource(static_cast<byte *>(plain), size, true,
                            new StreamTransformationFilter(e, new ArraySink(
                                            static_cast<byte *>(buffer),
                                            size)));

	} catch (const CryptoPP::Exception& e) {
                std::cerr << e.what() << std::endl;
                return SECNFS_CRYPTO_ERROR;
	}

        return SECNFS_OKAY;
}


secnfs_s secnfs_decrypt(secnfs_key_t key,
                        secnfs_key_t iv,
                        uint64_t offset,
                        uint64_t size,
                        void *cipher,
                        void *buffer) {
        return secnfs_encrypt(key, iv, offset, size, cipher, buffer);
}


secnfs_s secnfs_create_context(secnfs_context_t *secnfs_context) {
        secnfs_context->data = new secnfs::Context();
        return SECNFS_OKAY;
}


void secnfs_destroy_context(secnfs_context_t *secnfs_context) {
        secnfs::Context *context = get_context(secnfs_context);
        delete context;
}


secnfs_s secnfs_create_keyfile(secnfs_key_t *fek,
                               secnfs_key_t *iv,
                               void *keyfile) {
        // TODO: generate key file based on list of proxies.
}


#ifdef __cplusplus
}
#endif
