/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @author Ming Chen <v.mingchen@gmail.com>
 */

#include "secnfs_lib.h"

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/filters.h>
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StringStore;


#include <cryptopp/rsa.h>
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

namespace secnfs {

RSAKeyPair::RSAKeyPair(bool create) {
        if (create) {
                AutoSeededRandomPool rnd;
                pri_.GenerateRandomWithKeySize(rnd, RSAKeyLength);
                pub_.Initialize(pri_.GetModulus(), pri_.GetPublicExponent());
        }
}


bool RSAKeyPair::operator==(const RSAKeyPair &other) const {
        return IsSamePrivateKey(pri_, other.pri_) &&
                IsSamePublicKey(pub_, other.pub_);
}


bool RSAKeyPair::operator!=(const RSAKeyPair &other) const {
        return !(*this == other);
}


bool RSAKeyPair::Verify() const {
        // TODO implement this
        return true;
}


void EncodeKey(const RSAFunction& key, std::string *result) {
        key.DEREncode(StringSink(*result).Ref());
}


void DecodeKey(RSAFunction *key, const std::string &code) {
        key->BERDecode(StringStore(code).Ref());
}


void RSAEncrypt(const RSA::PublicKey &pub_key, const std::string &plain,
                std::string *cipher) {
        AutoSeededRandomPool prng;
        RSAES_OAEP_SHA_Encryptor e(pub_key);
        StringSource ss(plain, true,
                new PK_EncryptorFilter(prng, e,
                        new StringSink(*cipher)));
}


void RSADecrypt(const RSA::PrivateKey &pri_key, const std::string &cipher,
                std::string *recovered) {
        AutoSeededRandomPool prng;
        RSAES_OAEP_SHA_Decryptor d(pri_key);
        StringSource ss(cipher, true,
                new PK_DecryptorFilter(prng, d,
                        new StringSink(*recovered)));
}

};
