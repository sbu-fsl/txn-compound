/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Test secnfs.proto
 */

#include "secnfs.pb.h"

#include <gtest/gtest.h>

#include <iostream>
#include <fstream>

using namespace secnfs;

static void VerifyKeyFile(const KeyFile &f1, const KeyFile &f2) {
        EXPECT_EQ(f1.signature(), f2.signature());
        EXPECT_EQ(f1.creator(), f2.creator());
        EXPECT_EQ(f1.key_blocks_size(), f2.key_blocks_size());
        for (int i = 0; i < f1.key_blocks_size(); ++i) {
                const KeyBlock &b1 = f1.key_blocks(i);
                const KeyBlock &b2 = f2.key_blocks(i);
                EXPECT_EQ(b1.proxy_name(), b2.proxy_name());
                EXPECT_EQ(b1.encrypted_key(), b2.encrypted_key());
        }
}

TEST(KeyFileTest, Basic) {
        // create a key_file.
        KeyFile file1;
        file1.set_creator("nfs4sec");
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


TEST(SecureContextConfigTest, Basic) {
        SecureContextConfig config;
        config.set_name("secure-context");
        config.set_pub_key("pub-key");
        config.set_pri_key("pri-key");

        KeyBlock *block = config.add_proxies();
        block->set_proxy_name("proxy1");
        block->set_encrypted_key("key");

        std::ofstream output("/tmp/secure_context.txt");
        EXPECT_TRUE(config.SerializeToOstream(&output));
        output.close();

        SecureContextConfig config_copy;
        std::ifstream input("/tmp/secure_context.txt");
        EXPECT_TRUE(config_copy.ParseFromIstream(&input));

        EXPECT_EQ(config.name(), config_copy.name());
        EXPECT_EQ(config.pub_key(), config_copy.pub_key());
        EXPECT_EQ(config.pri_key(), config_copy.pri_key());
}
