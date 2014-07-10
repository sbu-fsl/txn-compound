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
using CryptoPP::AuthenticatedDecryptionFilter;

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
        memcpy(key->bytes, sk.data(), SECNFS_KEY_LENGTH);
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


/**
 * @brief Generate a key and an IV from a crypto PRNG.
 */
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
                        void *buffer)
{
        return secnfs_encrypt(key, iv, offset, size, cipher, buffer);
}


secnfs_s secnfs_auth_encrypt(secnfs_key_t key, secnfs_key_t iv,
                             uint64_t offset, uint64_t size, const void *plain,
                             uint64_t auth_size, const void *auth_msg,
                             void *buffer, void *tag)
{
        if (round_up(offset, AES::BLOCKSIZE) != offset ||
            round_up(size, AES::BLOCKSIZE) != size) {
                // We require offset and size to be aligned, otherwise, the
                // misaligned part will not be authenticated.
                return SECNFS_NOT_ALIGNED;
        }

        incr_ctr(&iv, SECNFS_KEY_LENGTH, offset / AES::BLOCKSIZE);

        try {
                GCM< AES, GCM_64K_Tables >::Encryption e;
                e.SetKeyWithIV(key.bytes, SECNFS_KEY_LENGTH, iv.bytes,
                               SECNFS_KEY_LENGTH);

                AuthenticatedEncryptionFilter aef(
                                e, new ArraySink(static_cast<byte *>(buffer),
                                                 size + TAG_SIZE), false,
                                TAG_SIZE);

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
                               uint64_t offset, uint64_t size,
                               const void *cipher, uint64_t auth_size,
                               const void *auth_msg, const void *tag,
                               void *buffer)
{
        if (round_up(offset, AES::BLOCKSIZE) != offset ||
            round_up(size, AES::BLOCKSIZE) != size) {
                // We require offset and size to be aligned, otherwise, the
                // misaligned part will not be authenticated.
                return SECNFS_NOT_ALIGNED;
        }

        incr_ctr(&iv, SECNFS_KEY_LENGTH, offset / AES::BLOCKSIZE);

        try {
                GCM< AES, GCM_64K_Tables >::Decryption d;
                d.SetKeyWithIV(key.bytes, SECNFS_KEY_LENGTH, iv.bytes,
                               SECNFS_KEY_LENGTH);

                AuthenticatedDecryptionFilter adf(
                        d, NULL,
                        AuthenticatedDecryptionFilter::MAC_AT_END |
                        AuthenticatedDecryptionFilter::THROW_EXCEPTION,
                        TAG_SIZE);

                adf.ChannelPut("AAD", static_cast<const byte *>(auth_msg),
                               auth_size);
                adf.ChannelPut("", static_cast<const byte *>(cipher), size);
                adf.ChannelPut("", static_cast<const byte *>(tag), TAG_SIZE);
                adf.ChannelMessageEnd("");

                if (!adf.GetLastResult()) {
                        std::cerr << "verification failed" << std::endl;
                        return SECNFS_NOT_VERIFIED;
                }

                adf.SetRetrievalChannel("");
                uint64_t n = adf.MaxRetrievable();
                if (n != size) {
                        std::cerr << "message length mismatch" << std::endl;
                        return SECNFS_CRYPTO_ERROR;
                }

                adf.Get(static_cast<byte *>(buffer), n);

        } catch (CryptoPP::HashVerificationFilter::HashVerificationFailed &e) {
                std::cerr << e.what() << std::endl;
                return SECNFS_NOT_VERIFIED;
        } catch (CryptoPP::Exception &e) {
                std::cerr << e.what() << std::endl;
                return SECNFS_CRYPTO_ERROR;
        }

        return SECNFS_OKAY;
}


secnfs_s secnfs_create_context(secnfs_info_t *info)
{
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


secnfs_s secnfs_init_info(secnfs_info_t *info)
{
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


static inline secnfs_key_t *new_secnfs_key()
{
        return static_cast<secnfs_key_t*>(calloc(1, sizeof(secnfs_key_t)));
}


void secnfs_destroy_context(secnfs_info_t *info)
{
        delete get_context(info);
}


secnfs_s create_meta(FileMeta *meta,
                     secnfs_key_t *fek, secnfs_key_t *iv,
                     uint64_t filesize)
{
        uint8_t filesize_buf[8];
        secnfs_s ret;

        uint64_to_bytes(filesize_buf, filesize);

        ret = secnfs_encrypt(*fek, *iv, 0, 8, filesize_buf, filesize_buf);
        if (ret != SECNFS_OKAY)
                return ret;

        meta->set_filesize(filesize_buf, 8);

        return SECNFS_OKAY;
}


secnfs_s read_meta(const FileMeta &meta,
                   secnfs_key_t *fek, secnfs_key_t *iv,
                   uint64_t *filesize)
{
        uint8_t filesize_buf[8];
        secnfs_s ret;

        memcpy(filesize_buf, meta.filesize().data(), 8);

        ret = secnfs_decrypt(*fek, *iv, 0, 8, filesize_buf, filesize_buf);
        if (ret != SECNFS_OKAY)
                return ret;

        uint64_from_bytes(filesize_buf, filesize);

        return SECNFS_OKAY;
}


secnfs_s secnfs_create_header(secnfs_info_t *info,
                              secnfs_key_t *fek,
                              secnfs_key_t *iv,
                              uint64_t filesize,
                              void **buf,
                              uint32_t *len,
                              void **kf_cache)
{
        Context *ctx = get_context(info);
        FileHeader header;
        KeyFile *kf;
        secnfs_s ret;

        kf = static_cast<KeyFile *>(*kf_cache);
        if (!kf) {
                kf = new KeyFile;
                *kf_cache = kf;
        }
        header.set_allocated_keyfile(kf);

        if (!kf->has_creator()) { // check cache
                ctx->GenerateKeyFile(fek->bytes, iv->bytes,
                                SECNFS_KEY_LENGTH, kf);
                kf->set_creator(ctx->name());
        }

        ret = create_meta(header.mutable_meta(), fek, iv, filesize);
        if (ret != SECNFS_OKAY) {
                LOG(ERROR) << "create meta failed";
                goto out;
        }

        if (!EncodeMessage(header, buf, len, FILE_HEADER_SIZE)) {
                LOG(ERROR) << "cannot write keyfile";
                ret = SECNFS_WRONG_CONFIG;
                goto out;
        }

        assert(*len == FILE_HEADER_SIZE);

out:
        header.release_keyfile(); /* avoid cleanup by header's destructor */

        return SECNFS_OKAY;
}


secnfs_s secnfs_read_header(secnfs_info_t *info,
                            void *buf,
                            uint32_t buf_size,
                            secnfs_key_t *fek,
                            secnfs_key_t *iv,
                            uint64_t *filesize,
                            uint32_t *len,
                            void **kf_cache)
{
        Context *ctx = get_context(info);

        FileHeader header;
        KeyFile *kf;

        assert(*kf_cache == NULL);
        kf = new KeyFile;
        *kf_cache = kf;
        header.set_allocated_keyfile(kf);

        if (!DecodeMessage(&header, buf, buf_size, len)) {
                LOG(ERROR) << "cannot decode keyfile";
                goto err;
        }
        assert(header.ByteSize() == *len);

        str_to_key(kf->iv(), iv);

        for (int i = 0; i < kf->key_blocks_size(); ++i) {
                const KeyBlock &kb = kf->key_blocks(i);
                if (kb.proxy_name() == ctx->name()) {
                        std::string rkey;
                        RSADecrypt(ctx->pri_key(), kb.encrypted_key(), &rkey);
                        str_to_key(rkey, fek);
                        memmove(fek->bytes, rkey.c_str(), SECNFS_KEY_LENGTH);
                        header.release_keyfile();
                        return read_meta(header.meta(), fek, iv, filesize);
                }
        }

        LOG(ERROR) << "key not found for " << ctx->name();

err:
        header.release_keyfile();
        delete kf;
        *kf_cache = NULL;

        return SECNFS_KEYFILE_ERROR;
}

void secnfs_release_keyfile_cache(void **kf_cache)
{
        delete static_cast<KeyFile *>(*kf_cache);
        *kf_cache = NULL;
}

#ifdef __cplusplus
}
#endif
