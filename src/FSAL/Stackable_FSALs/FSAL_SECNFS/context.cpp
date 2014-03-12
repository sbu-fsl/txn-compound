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

#include <cryptopp/rsa.h>
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include <cryptopp/filters.h>
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::StringSource;
using CryptoPP::StringSink;

namespace secnfs {

// TODO accept option
Context::Context(bool create) : key_pair_(create) {
        if (!create) {
                // TODO check existence of the file
                Load(SecNFSContextPath);
        }
}


Context::~Context() {
        Unload(SecNFSContextPath);
}


void Context::AddProxy(const SecureProxy &proxy) {
        proxies_.push_back(proxy);
}


void Context::Load(const std::string &filename) {
        SecureContextConfig config;
        std::ifstream input(filename.c_str());
        assert(config.ParseFromIstream(&input));

        name_ = config.name();
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


void Context::GenerateKeyFile(secnfs_key_t *key, secnfs_key_t *iv, KeyFile *kf)
{
        AutoSeededRandomPool prng;
        prng.GenerateBlock(key->bytes, SECNFS_KEY_LENGTH);
        prng.GenerateBlock(iv->bytes, SECNFS_KEY_LENGTH);

        kf->set_iv(static_cast<char *>(iv->bytes));

        for (size_t i = 0; i < proxies_.size(); ++i) {
                const SecureProxy &p = proxies_[i];
                KeyBlock *block = kf->add_key_blocks();
                block->set_proxy_name(p.name_);

                std::string *encrypted_key = block->mutable_encrypted_key();

                RSAES_OAEP_SHA_Encryptor e(p.key_);
                StringSource ss1(key->bytes, true,
                        new PK_EncryptorFilter(prng, e,
                                new StringSink(*encrypted_key)));

        }
}

};
