/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @file  secnfs.cpp
 * @brief Encrypt and decrypt data
 */

#include <sys/stat.h>
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

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

using namespace secnfs;

#include <assert.h>
#include <error.h>

static inline Context *get_context(secnfs_info_t *info) {
        return static_cast<Context *>(info->context);
}

static inline ProxyList *get_proxies(secnfs_info_t *info) {
        return static_cast<ProxyList*>(info->proxy_list);
}

#ifdef __cplusplus
extern "C" {
#endif

static void str_to_key(const std::string &sk, secnfs_key_t *key) {
        assert(sk.length() == SECNFS_KEY_LENGTH);
        memmove(key->bytes, sk.c_str(), SECNFS_KEY_LENGTH);
        key->bytes[SECNFS_KEY_LENGTH] = 0;
}


secnfs_key_t *incr_ctr(secnfs_key_t *iv, unsigned size, int incr)
{
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


void generate_key_and_iv(secnfs_key_t *key, secnfs_key_t *iv)
{
        AutoSeededRandomPool prng;
        prng.GenerateBlock(key->bytes, SECNFS_KEY_LENGTH);
        prng.GenerateBlock(iv->bytes, SECNFS_KEY_LENGTH);
}

/*
 * @brief Check if n is aligned by the encryption block size
 */
static int is_block_aligned(uint64_t n) { return !(n & (AES::BLOCKSIZE - 1)); }

static uint64_t round_up_block(uint64_t n)
{
        return (n + AES::BLOCKSIZE - 1) & ~(AES::BLOCKSIZE - 1);
}

static secnfs_s offset_aligned_encrypt(secnfs_key_t key,
                                       secnfs_key_t iv,
                                       uint64_t offset,
                                       uint64_t size,
                                       void *plain,
                                       void *buffer)
{
        assert(is_block_aligned(offset));

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

secnfs_s secnfs_encrypt(secnfs_key_t key,
                        secnfs_key_t iv,
                        uint64_t offset,
                        uint64_t size,
                        void *plain,
                        void *buffer)
{
        secnfs_s ret;
        uint64_t left_over = round_up_block(offset) - offset;

        if (left_over > 0) {
                uint64_t pad = AES::BLOCKSIZE - left_over;
                uint64_t aligned_offset = offset - pad;
                byte pbuf[AES::BLOCKSIZE];
                byte cbuf[AES::BLOCKSIZE];

                memmove(pbuf + pad, plain, left_over);
                ret = offset_aligned_encrypt(key, iv, aligned_offset,
                                             AES::BLOCKSIZE, pbuf, cbuf);
                if (ret != SECNFS_OKAY)
                        return ret;
                memmove(buffer, cbuf + pad, left_over);
        }

        return offset_aligned_encrypt(key, iv,
                                      offset + left_over,
                                      size - left_over,
                                      static_cast<byte *>(plain) + left_over,
                                      static_cast<byte *>(buffer) + left_over);
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
        int ret;
        struct stat st;
        Context *ctx = new Context(info);

        assert(ctx);

        ret = ::stat(info->context_cache_file, &st);
        if (ret == 0) {
                ctx->Load(info->context_cache_file);
                SECNFS_I("secnfs context loaded");
        } else if (errno == ENOENT) {
                assert(info->create_if_no_context);
                SECNFS_I("new secnfs context created");
                ctx->Unload(info->context_cache_file);
                SECNFS_I("context written to %s", info->context_cache_file);
        } else {
                error(ret, errno, "cannot access or create %s",
                      info->context_cache_file);
                return SECNFS_WRONG_CONFIG;
        }

        info->context = ctx;
        info->context_size = sizeof(Context);

        return SECNFS_OKAY;
}


secnfs_s secnfs_init_proxies(secnfs_info_t *info) {
        ProxyList *plist = new ProxyList();

        std::ifstream input(info->plist_file);
        if (!plist->ParseFromIstream(input)) {
                SECNFS_ERR("cannot read proxy list from %s", info->plist_file);
                return SECNFS_WRONG_CONFIG;
        }

        info->proxy_list = plist;

        return SECNFS_OKAY;
}


secnfs_s secnfs_init_info(secnfs_info_t *info) {
        secnfs_s ss;

        if ((ss = secnfs_create_context(info)) != SECNFS_OKAY) {
                SECNFS_ERR("cannot create context: %d", ss);
                return ss;
        }

        if ((ss == secnfs_init_proxies(info)) != SECNFS_OKAY) {
                SECNFS_ERR("cannot init proxy list: %d", ss);
                return ss;
        }

        return SECNFS_OKAY;
}


static inline secnfs_key_t *new_secnfs_key() {
        return static_cast<secnfs_key_t*>(calloc(1, sizeof(secnfs_key_t)));
}


void secnfs_destroy_context(secnfs_info_t *info) {
        delete get_context(info);
        delete get_proxies(info);
}


secnfs_s secnfs_create_keyfile(secnfs_info_t *info,
                               secnfs_key_t *fek,
                               secnfs_key_t *iv,
                               void **keyfile,
                               uint32_t *kf_len) {
        Context *ctx = get_context(info);

        KeyFile kf;
        ctx->GenerateKeyFile(fek->bytes, iv->bytes,
                             SECNFS_KEY_LENGTH, &kf);
        kf.set_creator(ctx->name());

        assert(EncodeMessage(kf, keyfile, kf_len, KEY_FILE_SIZE));

        assert(*kf_len == KEY_FILE_SIZE);

        return SECNFS_OKAY;
}


secnfs_s secnfs_read_file_key(secnfs_info_t *info,
                              void *buf,
                              uint32_t buf_size,
                              secnfs_key_t *fek,
                              secnfs_key_t *iv,
                              uint32_t *kf_len) {
        Context *ctx = get_context(info);
        KeyFile kf;

        assert(DecodeMessage(&kf, buf, buf_size, kf_len));
        assert(kf.ByteSize() == *kf_len);

        str_to_key(kf.iv(), iv);

        for (int i = 0; i < kf.key_blocks_size(); ++i) {
                const KeyBlock &kb = kf.key_blocks(i);
                if (kb.proxy_name() == ctx->name()) {
                        std::string rkey;
                        RSADecrypt(ctx->pri_key(), kb.encrypted_key(), &rkey);
                        str_to_key(rkey, fek);
                        memmove(fek->bytes, rkey.c_str(), SECNFS_KEY_LENGTH);
                        break;
                }
        }

        return SECNFS_OKAY;
}


#ifdef __cplusplus
}
#endif
