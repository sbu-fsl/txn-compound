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

const int MSG_SIZE = 4096;

#define EXPECT_OKAY(x) EXPECT_EQ(x, SECNFS_OKAY)

#define EXPECT_SAME(buf_a, buf_b, len) EXPECT_EQ(memcmp(buf_a, buf_b, len), 0)

class EncryptTest : public ::testing::Test {
protected:
        virtual void SetUp() {
                prng.GenerateBlock(key.bytes, SECNFS_KEY_LENGTH);
                prng.GenerateBlock(iv.bytes, SECNFS_KEY_LENGTH);
                prng.GenerateBlock(plain, sizeof(plain));
                ASSERT_EQ(secnfs_encrypt(key, iv, 0, MSG_SIZE, plain, cipher),
                          SECNFS_OKAY);
        }

        AutoSeededRandomPool prng;
        secnfs_key_t key;
        secnfs_key_t iv;
        byte plain[MSG_SIZE];
        byte cipher[MSG_SIZE];
};

TEST_F(EncryptTest, Basic) {
        byte decrypted[MSG_SIZE];

        EXPECT_OKAY(secnfs_decrypt(key, iv, 0, MSG_SIZE, cipher, decrypted));
        EXPECT_SAME(plain, decrypted, MSG_SIZE);
}

TEST_F(EncryptTest, TwoSteps) {
        secnfs_key_t myiv = iv;
        byte decrypted[MSG_SIZE];
        int half_len = MSG_SIZE / 2;

        EXPECT_OKAY(secnfs_decrypt(key, myiv, 0, half_len, cipher, decrypted));
        incr_ctr(&myiv, SECNFS_KEY_LENGTH, half_len / AES::BLOCKSIZE);
        EXPECT_OKAY(secnfs_decrypt(key, myiv, 0, half_len, cipher + half_len,
                                   decrypted + half_len));

        EXPECT_SAME(plain, decrypted, MSG_SIZE);
}

TEST_F(EncryptTest, BlockByBlock) {
        secnfs_key_t myiv = iv;
        byte block[MSG_SIZE];

        for (int i = 0; i < MSG_SIZE / AES::BLOCKSIZE; ++i) {
		byte *cipherp = cipher + i * AES::BLOCKSIZE;

                EXPECT_OKAY(secnfs_decrypt(key, myiv, 0, AES::BLOCKSIZE,
                                           cipherp, block));

                incr_ctr(&myiv, SECNFS_KEY_LENGTH, 1);

                EXPECT_SAME(plain + i * AES::BLOCKSIZE, block, AES::BLOCKSIZE);
        }
}
