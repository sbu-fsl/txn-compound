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
Context::Context(const secnfs_info_t *secnfs_info, bool create)
                : name_(secnfs_info->secnfs_name), key_pair_(create) {
        if (!create) {
                Load(secnfs_info->context_cache_file);
        }
}


Context::~Context() {}


void Context::AddProxy(const SecureProxy &proxy) {
        proxies_.push_back(proxy);
}


void Context::Load(const std::string &filename) {
        SecureContextConfig config;
        std::ifstream input(filename.c_str());
        assert(config.ParseFromIstream(&input));

        assert(name_ == config.name());

        DecodeKey(&(key_pair_.pri_), config.pri_key());
        DecodeKey(&(key_pair_.pub_), config.pub_key());

        proxies_.resize(config.proxies_size());
        for (size_t i = 0; i < proxies_.size(); ++i) {
                SecureProxy &p = proxies_[i];
                const KeyBlock &block = config.proxies(i);
                p.name_ = block.proxy_name();
                DecodeKey(&(p.key_), block.encrypted_key());
        }
}


void Context::Unload(const std::string &filename) {
        // TODO encryption the file
        SecureContextConfig config;
        config.set_name(name_);
        EncodeKey(key_pair_.pri_, config.mutable_pri_key());
        EncodeKey(key_pair_.pub_, config.mutable_pub_key());
        assert(config.pri_key().length() > 0);
        assert(config.pub_key().length() > 0);

        for (size_t i = 0; i < proxies_.size(); ++i) {
                const SecureProxy &p = proxies_[i];
                KeyBlock *block = config.add_proxies();
                block->set_proxy_name(p.name_);
                EncodeKey(p.key_, block->mutable_encrypted_key());
        }

        std::ofstream output(filename.c_str());
        assert(config.SerializeToOstream(&output));
        output.close();
}


void Context::GenerateKeyFile(byte *key, byte *iv, int len, KeyFile *kf)
{
        AutoSeededRandomPool prng;
        prng.GenerateBlock(key, len);
        prng.GenerateBlock(iv, len);

        kf->set_iv(reinterpret_cast<char *>(iv));

        for (size_t i = 0; i < proxies_.size(); ++i) {
                const SecureProxy &p = proxies_[i];
                KeyBlock *block = kf->add_key_blocks();
                block->set_proxy_name(p.name_);

                RSAEncrypt(p.key_, reinterpret_cast<char *>(key),
                           block->mutable_encrypted_key());
        }
}

};
