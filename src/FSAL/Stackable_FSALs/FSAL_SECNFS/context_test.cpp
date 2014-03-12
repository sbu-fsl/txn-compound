/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Test context.cpp
 */

#include "context.h"
#include "secure_proxy.h"

#include <string>
using std::string;

#include <gtest/gtest.h>

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

using namespace secnfs;

TEST(ContextTest, Basic) {
        Context context(true);
        context.name_ = "context-test";

        AutoSeededRandomPool rnd;
        RSA::PrivateKey pri_key;
        pri_key.GenerateRandomWithKeySize(rnd, RSAKeyLength);

        context.AddProxy(SecureProxy("proxy1", pri_key));
        context.AddProxy(SecureProxy("proxy2", pri_key));

        const string filename = "/tmp/secure-context-test.conf";
        context.Unload(filename);

        Context new_context(true);
        new_context.Load(filename);

        EXPECT_EQ(context.name_, new_context.name_);
        EXPECT_EQ(context.key_pair_, new_context.key_pair_);
}
