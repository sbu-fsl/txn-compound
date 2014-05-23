/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @file  secnfs.cpp
 * @brief Encrypt and decrypt data
 */

#include <sys/stat.h>
#include <glog/logging.h>
#include "secnfs.h"
#include "secnfs.pb.h"
#include "context.h"
#include "secnfs_lib.h"
#include "proxy_manager.h"

#include <iostream>
#include <fstream>
#include <string>

#include <cryptopp/filters.h>
using CryptoPP::ArraySource;
using CryptoPP::ArraySink;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AuthenticatedEncryptionFilter;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/ccm.h>
using CryptoPP::CTR_Mode;

#include <cryptopp/rsa.h>
using CryptoPP::RSA;

#include <cryptopp/gcm.h>
using CryptoPP::GCM;
using CryptoPP::GCM_64K_Tables;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

using namespace secnfs;

#include <assert.h>
#include <error.h>

static inline Context *get_context(secnfs_info_t *info) {
        return static_cast<Context *>(info->context);
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
        uint64_t left_over = round_up(offset, AES::BLOCKSIZE) - offset;

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


/*
 * See http://www.cryptopp.com/wiki/GCM
 *
 * REQUIRES:
 *  1. buffer is large enough for the data and the tag
 *  2. offset and size is aligned to AES::BLOCKSIZE (128bit)
 */
secnfs_s secnfs_auth_encrypt(secnfs_key_t key, secnfs_key_t iv,
                             uint64_t offset, uint64_t size, void *plain,
                             uint64_t auth_size, void *auth_msg,
                             void *buffer, void *tag)
{
        secnfs_s ret;

        if (round_up(offset, AES::BLOCKSIZE) != offset ||
            round_up(size, AES::BLOCKSIZE) != size) {
                // We require offset and size to be aligned, otherwise, the
                // misaligned part will not be authenticated.
                return SECNFS_NOT_ALIGNED;
        }

        incr_ctr(&iv, SECNFS_KEY_LENGTH, offset / AES::BLOCKSIZE);

        try {
                GCM< AES, GCM_64K_Tables >::Encryption e;
                e.SetKeyWithIV(key.bytes, AES::DEFAULT_KEYLENGTH, iv.bytes);

                AuthenticatedEncryptionFilter aef(
                                e, new ArraySink(static_cast<byte *>(buffer),
                                                 size), false, TAG_SIZE);

                aef.ChannelPut("AAD", static_cast<const byte *>(auth_msg),
                               auth_size);
                aef.ChannelMessageEnd("AAD");

                aef.ChannelPut("", static_cast<const byte *>(plain), size);
                aef.ChannelMessageEnd("");
        } catch (CryptoPP::Exception &e) {
                std::cerr << e.what() << std::endl;
                return SECNFS_CRYPTO_ERROR;
        }

        memmove(tag, static_cast<byte *>(buffer) + size, TAG_SIZE);
        return SECNFS_OKAY;
}


secnfs_s secnfs_verify_decrypt(secnfs_key_t key, secnfs_key_t iv,
                               uint64_t offset, uint64_t size, void *cipher,
                               uint64_t auth_size, void *auth_msg, void *tag,
                               void *buffer)
{
        return SECNFS_OKAY;
}


secnfs_s secnfs_create_context(secnfs_info_t *info) {
        int ret;
        struct stat st;
        Context *ctx = new Context(info->secnfs_name);
        ProxyManager& pm = ctx->proxy_manager();
        bool new_context = false;

        assert(ctx);

        ret = ::stat(info->context_cache_file, &st);
        if (ret == 0) {
                ctx->Load(info->context_cache_file);
                LOG(INFO) << "secnfs context loaded";
        } else if (errno == ENOENT) {
                assert(info->create_if_no_context);
                if (ctx->AddCurrentProxy()) {
                        LOG(INFO) << "proxy added into list";
                } else {
                        LOG(ERROR) << "cannot add proxy into list";
                }
                ctx->Unload(info->context_cache_file);
                LOG(INFO) << "context written to " << info->context_cache_file;
                new_context = true;
        } else {
                error(ret, errno, "cannot access %s", info->context_cache_file);
        }

        ret = ::stat(info->plist_file, &st);
        if (ret == 0) {
                if (!pm.Load(info->plist_file)) {
                        LOG(ERROR) << "cannot load proxy list";
                        delete ctx;
                        return SECNFS_WRONG_CONFIG;
                }
        } else if (errno == ENOENT) {
                assert(new_context);
        } else {
                error(ret, errno, "cannot access %s", info->plist_file);
        }

        // add the newly created into the list if necessary
        if (new_context) {
                pm.Unload(info->plist_file);
        }

        info->context = ctx;
        info->context_size = sizeof(Context);

        return SECNFS_OKAY;
}


secnfs_s secnfs_init_info(secnfs_info_t *info) {
        secnfs_s ss;

        // Log files will be saved into /tmp/, for example
        // /tmp/secnfs.nfs4sec.mchen.log.INFO.20140331-073455.5871
        //
        // The log directory can be changed by setting:
        //      FLAGS_log_dir = "/some/log/directory";
        google::InitGoogleLogging("secnfs");
        LOG(INFO) << "Logging initialized";

        if ((ss = secnfs_create_context(info)) != SECNFS_OKAY) {
                LOG(ERROR) << "cannot create context: " << ss;
                return ss;
        }

        return SECNFS_OKAY;
}


static inline secnfs_key_t *new_secnfs_key() {
        return static_cast<secnfs_key_t*>(calloc(1, sizeof(secnfs_key_t)));
}


void secnfs_destroy_context(secnfs_info_t *info) {
        delete get_context(info);
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

        if (!EncodeMessage(kf, keyfile, kf_len, KEY_FILE_SIZE)) {
                LOG(ERROR) << "cannot write keyfile";
                return SECNFS_WRONG_CONFIG;
        }

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

        if (!DecodeMessage(&kf, buf, buf_size, kf_len)) {
                LOG(ERROR) << "cannot decode keyfile";
                return SECNFS_KEYFILE_ERROR;
        }

        assert(kf.ByteSize() == *kf_len);

        str_to_key(kf.iv(), iv);

        for (int i = 0; i < kf.key_blocks_size(); ++i) {
                const KeyBlock &kb = kf.key_blocks(i);
                if (kb.proxy_name() == ctx->name()) {
                        std::string rkey;
                        RSADecrypt(ctx->pri_key(), kb.encrypted_key(), &rkey);
                        str_to_key(rkey, fek);
                        memmove(fek->bytes, rkey.c_str(), SECNFS_KEY_LENGTH);
                        return SECNFS_OKAY;
                }
        }

        LOG(ERROR) << "key not found for " << ctx->name();

        return SECNFS_KEYFILE_ERROR;
}


#ifdef __cplusplus
}
#endif
