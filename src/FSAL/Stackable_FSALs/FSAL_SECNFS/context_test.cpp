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

class ContextTest : public ::testing::Test {
protected:
        ContextTest() : context_(true) {}
        virtual void SetUp() {
                context_.name_ = "context-test";
                RSA::PrivateKey pri_key;
                pri_key.GenerateRandomWithKeySize(prng_, RSAKeyLength);

                context_.AddProxy(SecureProxy("proxy1", pri_key));
                context_.AddProxy(SecureProxy("proxy2", pri_key));
        }

        AutoSeededRandomPool prng_;
        Context context_;
};


TEST_F(ContextTest, Basic) {
        const string filename = "/tmp/secure-context-test.conf";
        context_.Unload(filename);

        Context new_context(true);
        new_context.Load(filename);

        EXPECT_EQ(context_.name_, new_context.name_);
        EXPECT_EQ(context_.key_pair_, new_context.key_pair_);
}


TEST_F(ContextTest, GenerateKeyFileCorrectly) {

}
