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

void EncodeKey(const ASN1Object& key, std::string *result) {
        key.DEREncode(StringSink(*result).Ref());
}


void DecodeKey(ASN1Object *key, const std::string &code) {
        key.BERDecode(StringStore(code).Ref())
}

Context::Context(bool create) {
        if (create) { // TODO accept option
                AutoSeededRandomPool rnd;
                psk_pri_ = new RSA::PrivateKey();
                psk_pri_->GenerateRandomWithKeySize(rnd, 3072);
                psk_pub_ = new RSA::PublicKey(*rsa_pri);
        } else {
                // make the file configurable
                Load("/etc/secnfs-context.conf");
        }
}


Context::~Context() {
        delete psk_pri;
        delete psk_pub;
}


void Context::AddProxy(const SecureProxy &proxy) {
        proxies_.push_back(proxy);
}


void Context::Load(const std::string &filename) {
        SecureContextConfig config;
        std::ifstream input(filename);
        config.ParseFromIstream(&input);

        name_ = config.name();
        DecodeKey(psk_pri_, config.pri_key());
        DecodeKey(psk_pub_, config.pub_key());

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
        EncodeKey(*psk_pri_, config.mutable_pri_key());
        EncodeKey(*psk_pub_, config.mutable_pub_key());

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
