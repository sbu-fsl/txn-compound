/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Test context.cpp
 */

#include "secnfs_lib.h"

#include <string>
using std::string;

#include <gtest/gtest.h>

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

using namespace secnfs;

TEST(KeyCodingTest, Basic) {
        RSAKeyPair kp, kp_copy;
        string pri_str, pub_str;

        EncodeKey(kp.pri_, &pri_str);
        DecodeKey(&(kp_copy.pri_), pri_str);

        EncodeKey(kp.pub_, &pub_str);
        DecodeKey(&(kp_copy.pub_), pub_str);

        EXPECT_EQ(kp, kp_copy);
}
