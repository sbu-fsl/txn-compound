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


secnfs_s create_meta(FileHeader &header,
                     secnfs_key_t *fek, secnfs_key_t *iv,
                     uint64_t filesize, void *holes)
{
        secnfs_s ret;
        FileMeta meta;
        void *meta_buf;
        uint32_t meta_len;

        meta.set_filesize(filesize);
        static_cast<BlockMap *>(holes)->dump_to_pb(meta.mutable_holes());

        if (!EncodeMessage(meta, &meta_buf, &meta_len, FILE_META_SIZE)) {
                LOG(ERROR) << "cannot encode meta";
                ret = SECNFS_WRONG_CONFIG;
                goto out;
        }
        assert(meta_len == FILE_META_SIZE);

        ret = secnfs_encrypt(*fek, *iv, 0, meta_len, meta_buf, meta_buf);
        header.set_meta(meta_buf, meta_len);

out:
        free(meta_buf);

        return ret;
}


secnfs_s read_meta(FileHeader &header,
                   secnfs_key_t *fek, secnfs_key_t *iv,
                   uint64_t *filesize, void *holes)
{
        FileMeta meta;
        void *meta_buf;
        uint32_t meta_len;
        secnfs_s ret;

        meta_buf = malloc(FILE_META_SIZE);
        assert(header.meta().size() == FILE_META_SIZE);
        ret = secnfs_decrypt(*fek, *iv, 0, header.meta().size(),
                             const_cast<char *>(header.meta().data()),
                             meta_buf);
        if (ret != SECNFS_OKAY) {
                LOG(ERROR) << "cannot decrypt meta";
                goto out;
        }

        if (!DecodeMessage(&meta, meta_buf, FILE_META_SIZE, &meta_len)) {
                LOG(ERROR) << "cannot decode meta buffer";
                goto out;
        }

        *filesize = meta.filesize();
        static_cast<BlockMap *>(holes)->load_from_pb(meta.holes());

        ret = SECNFS_OKAY;
out:
        free(meta_buf);

        return ret;
}


secnfs_s secnfs_create_header(secnfs_info_t *info,
                              secnfs_key_t *fek,
                              secnfs_key_t *iv,
                              uint64_t filesize,
                              void *holes,
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
        // TODO handle header version

        ret = create_meta(header, fek, iv, filesize, holes);
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
        ret = SECNFS_OKAY;

out:
        header.release_keyfile(); /* avoid cleanup by header's destructor */

        return ret;
}


secnfs_s secnfs_read_header(secnfs_info_t *info,
                            void *buf,
                            uint32_t buf_size,
                            secnfs_key_t *fek,
                            secnfs_key_t *iv,
                            uint64_t *filesize,
                            void *holes,
                            uint32_t *len,
                            void **kf_cache)
{
        Context *ctx = get_context(info);
        FileHeader header;
        KeyFile *kf = NULL;

        assert(*kf_cache == NULL);
        kf = new KeyFile;
        if (!kf)
                goto err;
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
                        return read_meta(header, fek, iv, filesize, holes);
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


void *secnfs_alloc_blockmap()
{
        return new BlockMap;
}


void secnfs_release_blockmap(void **p)
{
        delete static_cast<BlockMap *>(*p);
        *p = NULL;
}


uint64_t secnfs_range_try_lock(void *p, uint64_t offset, uint64_t length)
{
        BlockMap *range_lock = static_cast<BlockMap *>(p);
        assert(length);
        return range_lock->try_insert(offset, length);
}


void secnfs_range_unlock(void *p, uint64_t offset, uint64_t length)
{
        BlockMap *range_lock = static_cast<BlockMap *>(p);
        assert(length);
        range_lock->remove_match(offset, length);
}


void secnfs_hole_add(void *p, uint64_t offset, uint64_t length)
{
        BlockMap *holes = static_cast<BlockMap *>(p);
        /* new hole is always at the end */
        assert(length);
        holes->push_back(offset, length);
        holes->print();
}


size_t secnfs_hole_remove(void *p, uint64_t offset, uint64_t length)
{
        BlockMap *holes = static_cast<BlockMap *>(p);
        size_t affected = holes->remove_overlap(offset, length);
        if (affected)
                holes->print();
        return affected;
}


// find next hole that contains offset or after offset
void secnfs_hole_find_next(void *p, uint64_t offset,
                           uint64_t *nxt_offset, uint64_t *nxt_length)
{
        BlockMap *holes = static_cast<BlockMap *>(p);
        holes->find_next(offset, nxt_offset, nxt_length);
}


bool secnfs_offset_in_hole(void *p, uint64_t offset)
{
        uint64_t hole_off, hole_len;
        secnfs_hole_find_next(p, offset, &hole_off, &hole_len);
        if (!hole_len)
                return 0;

        return hole_off <= offset;
}


#ifdef __cplusplus
}
#endif
