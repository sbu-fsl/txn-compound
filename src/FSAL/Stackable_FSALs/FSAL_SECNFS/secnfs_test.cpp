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
        size_t blocksize = AES::BLOCKSIZE;
        size_t keylength = AES::DEFAULT_KEYLENGTH;

        EXPECT_GE(blocksize, 128 / 8);
        EXPECT_EQ(SECNFS_KEY_LENGTH, keylength);
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

#include <stdio.h>
void dumpbytes(const void *data, size_t len) {
        const byte *bytes = (const byte *)data;
        for (int i = 0; i < len; ++i) {
                printf("%02x", bytes[i]);
        }
        printf("\n");
}


TEST_F(EncryptTest, AuthEncryptBasic) {
        std::string ptx(16, (char)0x00);
        std::string msg(16, (char)0x00);
        byte ctx[16 + 16];
        byte tag[16];
        // results from the bottom of www.cryptopp.com/wiki/GCM
        byte expected_ctx[16] = {0xa3, 0xb2, 0x2b, 0x84, 0x49, 0xaf, 0xaf,
                0xbc, 0xd6, 0xc0, 0x9f, 0x2c, 0xfa, 0x9d, 0xe2, 0xbe};
        byte expected_tag[16] = {0xa1, 0x98, 0x37, 0x54, 0x8e, 0x08, 0x99,
                0xac, 0xae, 0x93, 0x7d, 0x2c, 0x5f, 0x18, 0xdc, 0x2b};

        memset(&key_, 0, sizeof(key_));
        memset(&iv_, 0, sizeof(iv_));

        EXPECT_OKAY(secnfs_auth_encrypt(key_, iv_, 0, 16, ptx.c_str(), 16,
                                        msg.c_str(), ctx, tag));
        //dumpbytes(ctx, 32);
        EXPECT_SAME(ctx, expected_ctx, 16);
        EXPECT_SAME(tag, expected_tag, 16);

        byte recovered[16];
        EXPECT_OKAY(secnfs_verify_decrypt(key_, iv_, 0, 16, ctx, 16,
                                          msg.c_str(), tag, recovered));
}

TEST_F(EncryptTest, AuthEncryptVerify) {
        byte buffer[MSG_SIZE + TAG_SIZE];
        byte *tag = buffer + MSG_SIZE;
        byte recovered[MSG_SIZE];
        std::string msg = "MessagesToVerify";

        EXPECT_OKAY(secnfs_auth_encrypt(key_, iv_, 0, MSG_SIZE, plain_,
                                        msg.size(), msg.c_str(), buffer, tag));
        EXPECT_OKAY(secnfs_verify_decrypt(key_, iv_, 0, MSG_SIZE, buffer,
                                          msg.size(), msg.c_str(), tag,
                                          recovered));
        EXPECT_SAME(plain_, recovered, MSG_SIZE);

        // tamper msg to "Massage"
        msg[1] = 'a';
        EXPECT_EQ(SECNFS_NOT_VERIFIED,
                  secnfs_verify_decrypt(key_, iv_, 0, MSG_SIZE, buffer,
                                        msg.size(), msg.c_str(), tag,
                                        recovered));
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
        uint64_t filesize;
        void *buf;

        generate_key_and_iv(&key, &iv);
        EXPECT_OKAY(secnfs_create_header(info, &key, &iv, 88, &buf, &buf_size));

        secnfs_key_t rkey, riv;
        uint32_t header_len;

        EXPECT_OKAY(secnfs_read_header(info, buf, buf_size,
                                       &rkey, &riv, &filesize, &header_len));

        EXPECT_SAME(iv.bytes, riv.bytes, SECNFS_KEY_LENGTH);
        EXPECT_SAME(key.bytes, rkey.bytes, SECNFS_KEY_LENGTH);
        EXPECT_EQ(88, filesize);

        free(buf);
        delete context;
        delete info;
}

TEST(SecnfsDifTest, Serialization) {
        struct secnfs_dif secnfs_dif = {
                .version = 0x1234567890abcdef,
                .tag = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
                .unused = {0}
        };
        byte expected[48] = {0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12,
                             0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                             0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte secnfs_dif_buf[48];

        secnfs_dif_to_buf(&secnfs_dif, secnfs_dif_buf);
        EXPECT_SAME(expected, secnfs_dif_buf, 48);

        struct secnfs_dif secnfs_dif_new;
        secnfs_dif_from_buf(&secnfs_dif_new, secnfs_dif_buf);
        EXPECT_EQ(secnfs_dif.version, secnfs_dif_new.version);
        EXPECT_SAME(secnfs_dif.tag, secnfs_dif_new.tag, TAG_SIZE);
        EXPECT_SAME(secnfs_dif.unused, secnfs_dif_new.unused, DIF_UNUSED_SIZE);
}

#include "nfs_dix.h"
TEST(SecnfsDifTest, FillSdDif) {
        struct secnfs_dif secnfs_dif = {
                .version = 0x1234567890abcdef,
                .tag = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
                .unused = {0}
        };
        byte expected[64] = {0x00, 0x00, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56,
                             0x00, 0x00, 0x34, 0x12, 0x00, 0x11, 0x22, 0x33,
                             0x00, 0x00, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                             0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte secnfs_dif_buf[48];
        byte sd_dif_buf[64] = {0};

        secnfs_dif_to_buf(&secnfs_dif, secnfs_dif_buf);
        fill_sd_dif(sd_dif_buf, secnfs_dif_buf, PI_SECNFS_DIF_SIZE, 1);
        EXPECT_SAME(expected, sd_dif_buf, PI_SD_DIF_SIZE);

        struct secnfs_dif secnfs_dif_new;
        extract_from_sd_dif(sd_dif_buf, secnfs_dif_buf, PI_SECNFS_DIF_SIZE, 1);
        secnfs_dif_from_buf(&secnfs_dif_new, secnfs_dif_buf);
        EXPECT_EQ(secnfs_dif.version, secnfs_dif_new.version);
        EXPECT_SAME(secnfs_dif.tag, secnfs_dif_new.tag, TAG_SIZE);
        EXPECT_SAME(secnfs_dif.unused, secnfs_dif_new.unused, DIF_UNUSED_SIZE);
}

}
