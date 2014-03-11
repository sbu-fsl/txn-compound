/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Test context.cpp
 */

#include "context.h"

#include <string>
using std::string;

#include <gtest/gtest.h>

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

using secnfs::Context;

static void VerifyPrivateKey(const RSA::PrivateKey &k1,
                             const RSA::PrivateKey &k2) {
        EXPECT_EQ(k1.GetModulus(), k2.GetModulus());
        EXPECT_EQ(k1.GetPublicExponent(), k2.GetPublicExponent());
        EXPECT_EQ(k1.GetPrivateExponent(), k2.GetPrivateExponent());
}


TEST(ContextTest, Basic) {
        Context context(true);
        context.name_ = "context-test";

        AutoSeededRandomPool rnd;
        RSA::PrivateKey pri_key;
        pri_key.GenerateRandomWithKeySize(rnd, 3072);

        context.AddProxy(SecureProxy("proxy1", pri_key));
        contest.AddProxy(SecureProxy("proxy2", pri_key));

        const string filename = "secure-context-test.conf";
        context.Unload(filename);

        Context new_context();
        new_context.Load(filename);

        EXPECT_EQ(context.name_, new_context.name_);
        VerifyPrivateKey(*(context.psk_pri_), *(new_context.psk_pri_));
}
