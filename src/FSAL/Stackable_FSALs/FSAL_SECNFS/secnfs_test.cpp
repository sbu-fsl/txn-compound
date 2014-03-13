/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Test secnfs.cpp
 */

#include "secnfs.h"

#include <string>
using std::string;

#include <gtest/gtest.h>

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/aes.h>
using CryptoPP::AES;

const int MSG_SIZE = 40960;

#define EXPECT_OKAY(x) EXPECT_EQ(x, SECNFS_OKAY)

#define EXPECT_SAME(buf_a, buf_b, len) EXPECT_EQ(memcmp(buf_a, buf_b, len), 0)

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
