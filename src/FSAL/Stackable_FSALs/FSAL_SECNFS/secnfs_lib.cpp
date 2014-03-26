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

#include <google/protobuf/io/coded_stream.h>
using google::protobuf::io::CodedInputStream;
using google::protobuf::io::CodedOutputStream;

#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
using google::protobuf::io::ArrayInputStream;
using google::protobuf::io::ArrayOutputStream;

namespace secnfs {

RSAKeyPair::RSAKeyPair(bool create) {
        if (create) {
                AutoSeededRandomPool rnd;
                pri_.GenerateRandomWithKeySize(rnd, RSAKeyLength);
                pub_.Initialize(pri_.GetModulus(), pri_.GetPublicExponent());
        }
}

RSAKeyPair::RSAKeyPair(const std::string &pub, const std::string &pri) {
        DecodeKey(&pub_, pub);
        DecodeKey(&pri_, pri);
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


bool EncodeMessage(const google::protobuf::Message &msg, void **buf,
                   uint32_t *buf_size, uint32_t align) {
        uint32_t msg_size = msg.ByteSize();

        *buf_size = ((msg_size + sizeof(msg_size) + align - 1) / align) * align;
        *buf = malloc(*buf_size);

        assert(*buf);

        ArrayOutputStream aos(*buf, *buf_size);
        CodedOutputStream cos(&aos);
        cos.WriteLittleEndian32(msg_size);

        return msg.SerializeToCodedStream(&cos);
}


bool DecodeMessage(google::protobuf::Message *msg, void *buf,
                   uint32_t buf_size, uint32_t *msg_size) {
        ArrayInputStream ais(buf, buf_size);
        CodedInputStream cis(&ais);

        if (!cis.ReadLittleEndian32(msg_size)) {
                return false;
        }

        if (buf_size < *msg_size + 4) {
                return false;
        }

        cis.PushLimit(*msg_size);
        return msg->ParseFromCodedStream(&cis);
}

};
