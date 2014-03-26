/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @file  secnfs.cpp
 * @brief Encrypt and decrypt data
 */

#include "context.h"
#include "secnfs.pb.h"

#include <fstream>
#include <assert.h>

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

namespace secnfs {

// TODO accept option
Context::Context(const secnfs_info_t *secnfs_info)
                : name_(secnfs_info->secnfs_name) {
}


Context::~Context() {}


void Context::Load(const std::string &filename) {
        SecureContextConfig config;
        std::ifstream input(filename.c_str());
        assert(config.ParseFromIstream(&input));

        assert(name_ == config.name());

        DecodeKey(&(key_pair_.pri_), config.pri_key());
        DecodeKey(&(key_pair_.pub_), config.pub_key());
}


void Context::Unload(const std::string &filename) {
        // TODO encryption the file
        SecureContextConfig config;
        config.set_name(name_);
        EncodeKey(key_pair_.pri_, config.mutable_pri_key());
        EncodeKey(key_pair_.pub_, config.mutable_pub_key());
        assert(config.pri_key().length() > 0);
        assert(config.pub_key().length() > 0);

        std::ofstream output(filename.c_str());
        assert(config.SerializeToOstream(&output));
        output.close();
}


void Context::GenerateKeyFile(byte *key, byte *iv, int len, KeyFile *kf)
{
        AutoSeededRandomPool prng;
        prng.GenerateBlock(key, len);
        prng.GenerateBlock(iv, len);
        key[len] = iv[len] = 0;

        kf->set_iv(std::string(reinterpret_cast<char *>(iv), len));

        for (size_t i = 0; i < proxies_.size(); ++i) {
                const SecureProxy &p = proxies_[i];
                KeyBlock *block = kf->add_key_blocks();
                block->set_proxy_name(p.name_);

                RSAEncrypt(p.key_,
                           std::string(reinterpret_cast<char *>(key), len),
                           block->mutable_encrypted_key());
        }
}

};
