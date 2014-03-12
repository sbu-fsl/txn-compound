/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @author Ming Chen <v.mingchen@gmail.com>
 */

#include "secnfs_lib.h"

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringStore;

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

};
