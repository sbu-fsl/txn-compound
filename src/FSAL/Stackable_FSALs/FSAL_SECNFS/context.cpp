/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @file  secnfs.cpp
 * @brief Encrypt and decrypt data
 */

#include "context.h"
#include "secnfs.pb.h"

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

namespace secnfs {

// TODO accept option
Context::Context(bool create) : key_pair_(create) {
        if (!create) {
                // make the file configurable
                Load("/etc/secnfs-context.conf");
        }
}


Context::~Context() {}


void Context::AddProxy(const SecureProxy &proxy) {
        proxies_.push_back(proxy);
}


void Context::Load(const std::string &filename) {
        SecureContextConfig config;
        std::ifstream input(filename);
        config.ParseFromIstream(&input);

        name_ = config.name();
        DecodeKey(&(key_pair_.pri_), config.pri_key());
        DecodeKey(&(key_pair_.pub_), config.pub_key());

        proxies_.resize(config.proxies_size());
        for (size_t i = 0; i < proxies_; ++i) {
                const SecureProxy &p = proxies_[i];
                const KeyBlock &block = config.proxies(i);
                p->name_ = block->proxy_name();
                DecodeKey(&(p->key_), block->encrypted_key());
        }
}


void Context::Unload(const std::string &filename) {
        // TODO encryption the file
        SecureContextConfig config;
        config.set_name(name_);
        EncodeKey(key_pair_.pri_, config.mutable_pri_key());
        EncodeKey(key_pair_.pub_, config.mutable_pub_key());

        for (size_t i = 0; i < proxies_; ++i) {
                const SecureProxy &p = proxies_[i];
                KeyBlock *block = config.add_proxies();
                block->set_proxy_name(p->name_);
                EncodeKey(p->key_, block->mutable_encrypted_key());
        }

        std::ofstream output(filename);
        config.SerializeToOstream(&output);
}

};
