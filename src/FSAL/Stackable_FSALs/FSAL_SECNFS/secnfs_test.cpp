/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Test secnfs.cpp
 */

#include "secnfs.h"
#include "test_helper.h"

#include <string>
using std::string;

#include <gtest/gtest.h>

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/aes.h>
using CryptoPP::AES;

using namespace secnfs;

namespace secnfs_test {

const int MSG_SIZE = 40960;

TEST(KeyBlockSizeTest, KeyBlockSize) {
        EXPECT_GE(AES::BLOCKSIZE, 128 / 8);
        EXPECT_EQ(SECNFS_KEY_LENGTH, AES::DEFAULT_KEYLENGTH);
}

class EncryptTest : public ::testing::Test {
protected:
        virtual void SetUp() {
                prng_.GenerateBlock(key_.bytes, SECNFS_KEY_LENGTH);
                prng_.GenerateBlock(iv_.bytes, SECNFS_KEY_LENGTH);
                prng_.GenerateBlock(plain_, MSG_SIZE);
                ASSERT_EQ(secnfs_encrypt(key_, iv_, 0, MSG_SIZE, plain_,
                                         cipher_), SECNFS_OKAY);
        }

        AutoSeededRandomPool prng_;
        secnfs_key_t key_;
        secnfs_key_t iv_;
        byte plain_[MSG_SIZE];
        byte cipher_[MSG_SIZE];
};


TEST_F(EncryptTest, Basic) {
        byte decrypted[MSG_SIZE];

        EXPECT_OKAY(secnfs_decrypt(key_, iv_, 0, MSG_SIZE, cipher_, decrypted));
        EXPECT_SAME(plain_, decrypted, MSG_SIZE);
}


TEST_F(EncryptTest, TwoSteps) {
        secnfs_key_t myiv = iv_;
        byte decrypted[MSG_SIZE];
        int half_len = MSG_SIZE / 2;

        EXPECT_OKAY(secnfs_decrypt(key_, myiv, 0, half_len, cipher_,
                                   decrypted));

        incr_ctr(&myiv, SECNFS_KEY_LENGTH, half_len / AES::BLOCKSIZE);

        EXPECT_OKAY(secnfs_decrypt(key_, myiv, 0, half_len, cipher_ + half_len,
                                   decrypted + half_len));

        EXPECT_SAME(plain_, decrypted, MSG_SIZE);
}


TEST_F(EncryptTest, UnalignedBuf) {
        const int TESTSIZE = AES::BLOCKSIZE * 10;
        byte decrypted[TESTSIZE];

        // test unaligned buffer size
        for (int sz = 1; sz < TESTSIZE; ++sz) {
                decrypted[sz] = 0;
                EXPECT_OKAY(secnfs_decrypt(key_, iv_, 0, sz, cipher_,
                                           decrypted));
                EXPECT_SAME(plain_, decrypted, sz);
                // The decryption should not touch anything beyond sz bytes
                EXPECT_EQ(decrypted[sz], 0);
        }

        // test unaligned offsets
        for (int os = 1; os < TESTSIZE; ++os) {
                int sz = TESTSIZE - os;
                decrypted[sz] = 0;
                EXPECT_OKAY(secnfs_decrypt(key_, iv_, os, sz,
                                           cipher_ + os, decrypted));
                EXPECT_SAME(plain_ + os, decrypted, sz);
                // The decryption should not touch anything beyond sz bytes
                EXPECT_EQ(decrypted[sz], 0);
        }
}


TEST_F(EncryptTest, BlockByBlock) {
        secnfs_key_t myiv = iv_;
        byte block[MSG_SIZE];

        for (int i = 0; i < MSG_SIZE / AES::BLOCKSIZE; ++i) {
		byte *cipherp = cipher_ + i * AES::BLOCKSIZE;

                EXPECT_OKAY(secnfs_decrypt(key_, myiv, 0, AES::BLOCKSIZE,
                                           cipherp, block));

                incr_ctr(&myiv, SECNFS_KEY_LENGTH, 1);

                EXPECT_SAME(plain_ + i * AES::BLOCKSIZE, block, AES::BLOCKSIZE);
        }
}


TEST_F(EncryptTest, RandomOffsets) {
        const int size = 1024;
        byte block[size];

        for (int i = 0; i < 10; ++i) {
                uint32_t offset = prng_.GenerateWord32(0, MSG_SIZE - size);
                offset &= ~(AES::BLOCKSIZE - 1);  // round by BLOCKSIZE

                EXPECT_OKAY(secnfs_decrypt(key_, iv_, offset, size,
                                           cipher_ + offset, block));
                EXPECT_SAME(block, plain_ + offset, size);
        }
}


class SecnfsTest : public ::testing::Test {
protected:
        SecnfsTest() : context_(NewContextWithProxies(5)) {}
        ~SecnfsTest() { delete context_; }
        virtual void SetUp() {

        }

        Context *context_;
};


TEST(CreateKeyFileTest, Basic) {
        secnfs_info_t *info = NewSecnfsInfo(2);
        Context *context = static_cast<Context *>(info->context);
        secnfs_key_t key, iv;
        uint32_t buf_size;
        void *buf;

        EXPECT_OKAY(secnfs_create_keyfile(info, &key, &iv, &buf, &buf_size));

        secnfs_key_t rkey, riv;
        uint32_t kf_len;

        EXPECT_OKAY(secnfs_read_file_key(info, buf, buf_size,
                                         &rkey, &riv, &kf_len));

        EXPECT_SAME(iv.bytes, riv.bytes, SECNFS_KEY_LENGTH);
        EXPECT_SAME(key.bytes, rkey.bytes, SECNFS_KEY_LENGTH);

        free(buf);
        delete context;
        delete info;
}

}
