/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Test context.cpp
 */

#include "secnfs.h"
#include "context.h"
#include "secnfs_lib.h"
#include "secure_proxy.h"

#include <string>
using std::string;

#include <gtest/gtest.h>

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

using namespace secnfs;

class ContextTest : public ::testing::Test {
protected:
        ContextTest() : context_(&secnfs_info_, true) {}
        virtual void SetUp() {
                context_.name_ = "context-test";
                rsa_pri_key_.GenerateRandomWithKeySize(prng_, RSAKeyLength);

                context_.AddProxy(SecureProxy("proxy1", rsa_pri_key_));
                context_.AddProxy(SecureProxy("proxy2", rsa_pri_key_));
        }

        secnfs_info_t secnfs_info_;
        AutoSeededRandomPool prng_;
        Context context_;
        RSA::PrivateKey rsa_pri_key_;
};


TEST_F(ContextTest, Basic) {
        const string filename = "/tmp/secure-context-test.conf";
        context_.Unload(filename);

        secnfs_info_t info;
        strncpy(info.secnfs_name, context_.name_.c_str(), MAXPATHLEN);
        Context new_context(&info, true);
        new_context.Load(filename);

        EXPECT_EQ(context_.name_, new_context.name_);
        EXPECT_EQ(context_.key_pair_, new_context.key_pair_);
}


TEST_F(ContextTest, GenerateKeyFileCorrectly) {
        byte key[SECNFS_KEY_LENGTH + 1] = {0};
        byte iv[SECNFS_KEY_LENGTH + 1] = {0};
        KeyFile kf;

        context_.GenerateKeyFile(key, iv, SECNFS_KEY_LENGTH, &kf);

        string file_key(reinterpret_cast<char *>(key));
        for (size_t i = 0; i < kf.key_blocks_size(); ++i) {
                const KeyBlock &kb = kf.key_blocks(i);
                string recovered_key;
                RSADecrypt(rsa_pri_key_, kb.encrypted_key(), &recovered_key);
                EXPECT_EQ(recovered_key, file_key);
        }
}


TEST_F(ContextTest, TestCacheMap) {
        string key("Hello"), value("World");
        std::pair<std::string, std::string> item(key, value);

        {
                Context::hash_entry result;
                EXPECT_TRUE(context_.map_.insert(result, item));
        }

        Context::hash_entry entry;
        EXPECT_TRUE(context_.map_.find(entry, key));
        EXPECT_EQ(entry->second, value);
}
