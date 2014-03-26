/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Test secnfs.proto
 */

#include "secnfs.pb.h"

#include "secnfs_lib.h"

#include <gtest/gtest.h>

#include <iostream>
#include <fstream>

using namespace secnfs;

namespace secnfs_test {

static void VerifyKeyFile(const KeyFile& f1, const KeyFile& f2) {
        EXPECT_EQ(f1.signature(), f2.signature());
        EXPECT_EQ(f1.creator(), f2.creator());
        EXPECT_EQ(f1.iv(), f2.iv());
        EXPECT_EQ(f1.key_blocks_size(), f2.key_blocks_size());
        for (int i = 0; i < f1.key_blocks_size(); ++i) {
                const KeyBlock& b1 = f1.key_blocks(i);
                const KeyBlock& b2 = f2.key_blocks(i);
                EXPECT_EQ(b1.proxy_name(), b2.proxy_name());
                EXPECT_EQ(b1.encrypted_key(), b2.encrypted_key());
        }
}

TEST(KeyFileTest, Basic) {
        // create a key_file.
        KeyFile file1;
        file1.set_creator("nfs4sec");
        file1.set_iv("initvector");
        file1.set_signature("mysignature");

        KeyBlock* block = file1.add_key_blocks();
        block->set_proxy_name("crossroads");
        block->set_encrypted_key("abcd");

        block = file1.add_key_blocks();
        block->set_proxy_name("dolphin");
        block->set_encrypted_key("1234");

        // save key_file.
        std::ofstream output("/tmp/key_file.txt");
        EXPECT_TRUE(file1.SerializeToOstream(&output));
        output.close();

        // read the key_file and verify.
        KeyFile file2;
        std::ifstream input("/tmp/key_file.txt");
        EXPECT_TRUE(file2.ParseFromIstream(&input));
        VerifyKeyFile(file1, file2);
}


class SecureContextConfigTest : public ::testing::Test {
protected:
        virtual void SetUp() {
                config_.set_name("secure-context");
                config_.set_pub_key("pub-key");
                config_.set_pri_key("pri-key");

                //KeyBlock *block = config_.add_proxies();
                //block->set_proxy_name("proxy1");
                //block->set_encrypted_key("key");
        }

        SecureContextConfig config_;
};


TEST_F(SecureContextConfigTest, Basic) {
        std::ofstream output("/tmp/secure_context_config.txt");
        EXPECT_TRUE(config_.SerializeToOstream(&output));
        output.close();

        SecureContextConfig config_copy;
        std::ifstream input("/tmp/secure_context.txt");
        EXPECT_TRUE(config_copy.ParseFromIstream(&input));

        EXPECT_EQ(config_.DebugString(), config_copy.DebugString());
}


TEST_F(SecureContextConfigTest, EncodeDecodeCorrectly) {
        void *buf;
        uint32_t buf_size, msg_size;

        EXPECT_TRUE(EncodeMessage(config_, &buf, &buf_size, 1024));
        EXPECT_GT(buf_size, config_.ByteSize());

        SecureContextConfig config_copy;
        EXPECT_TRUE(DecodeMessage(&config_copy, buf, buf_size, &msg_size));

        EXPECT_EQ(config_.DebugString(), config_copy.DebugString());

        free(buf);
}


TEST(ProxyListTest, Basic) {
        ProxyList plist;
        ProxyList private_keys;

        for (int i = 1; i <= 3; ++i) {
                char buf[16];
                ProxyEntry *p = plist.add_proxies();
                snprintf(buf, 16, "proxy%d", i);
                p->set_name(buf);
                RSAKeyPair kp(true);
                EncodeKey(kp.pub_, p->mutable_name());

                ProxyEntry *pri = private_keys.add_proxies();
                pri->set_name(buf);
                EncodeKey(kp.pri_, pri->mutable_name());
        }

        // write proxy list and corresponding private keys out
        std::ofstream output_proxies("secure_proxies.txt");
        std::ofstream output_privates("secure_privates.txt");

        EXPECT_TRUE(plist.SerializeToOstream(&output_proxies));
        EXPECT_TRUE(private_keys.SerializeToOstream(&output_privates));

        output_proxies.close();
        output_privates.close();

        // write proxy list back
        std::ifstream input_proxies("secure_proxies.txt");
        std::ifstream input_privates("secure_privates.txt");

        ProxyList recovered_plist;
        ProxyList recovered_privates;
        EXPECT_TRUE(recovered_plist.ParseFromIstream(&input_proxies));
        EXPECT_TRUE(recovered_privates.ParseFromIstream(&input_privates));

        for (int i = 0; i < 3; ++i) {
                const ProxyEntry& p = recovered_plist.proxies(i);
                const ProxyEntry& pri = recovered_privates.proxies(i);

                RSAKeyPair kp(p.key(), pri.key());

                EXPECT_TRUE(kp.Verify());
        }
}

};
