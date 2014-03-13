/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @file  secnfs.cpp
 * @brief Encrypt and decrypt data
 */

#include "secnfs.h"
#include "secnfs.pb.h"
#include "context.h"
#include "secnfs_lib.h"

#include <iostream>
#include <string>

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

using namespace secnfs;

#include <assert.h>

static inline Context *get_context(secnfs_info_t *info) {
        return static_cast<Context *>(info->context);
}


#ifdef __cplusplus
extern "C" {
#endif

secnfs_key_t *incr_ctr(secnfs_key_t *iv, unsigned size, int incr) {
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


/*
 * @brief Check if n is aligned by the encryption block size
 */
static int is_block_aligned(uint64_t n) { return !(n & (AES::BLOCKSIZE - 1)); }

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


secnfs_s secnfs_create_context(secnfs_info_t *info) {
        info->context = new Context();
        info->context_size = sizeof(Context);
        assert(info->context);
        return SECNFS_OKAY;
}


static inline secnfs_key_t *new_secnfs_key() {
        return static_cast<secnfs_key_t*>(calloc(1, sizeof(secnfs_key_t)));
}


void secnfs_destroy_context(secnfs_info_t *info) {
        delete get_context(info);
}


secnfs_s secnfs_create_keyfile(secnfs_info_t *info,
                               secnfs_key_t **fek,
                               secnfs_key_t **iv,
                               void **keyfile,
                               int *kf_len) {
        *fek = new_secnfs_key();
        *iv = new_secnfs_key();
        Context *ctx = get_context(info);

        KeyFile kf;
        ctx->GenerateKeyFile((*fek)->bytes, (*iv)->bytes,
                             SECNFS_KEY_LENGTH, &kf);

        std::string kf_buf;
        assert(kf.SerializeToString(&kf_buf));

        *kf_len = kf_buf.length();
        *keyfile = malloc(*kf_len);
        memcpy(*keyfile, kf_buf.c_str(), *kf_len);

        return SECNFS_OKAY;
}


#ifdef __cplusplus
}
#endif
