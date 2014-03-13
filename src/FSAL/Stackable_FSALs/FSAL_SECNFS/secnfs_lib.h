/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @brief SECNFS library functions and classes.
 * @author Ming Chen <v.mingchen@gmail.com>
 */

#ifndef H_SECNFS_LIB
#define H_SECNFS_LIB

#include <string>

#include <cryptopp/rsa.h>
using CryptoPP::RSA;
using CryptoPP::RSAFunction;

namespace secnfs {

const int RSAKeyLength = 3072;

inline bool IsSamePrivateKey(const RSA::PrivateKey &k1,
                             const RSA::PrivateKey &k2) {
        return k1.GetModulus() == k2.GetModulus() &&
                k1.GetPublicExponent() == k2.GetPublicExponent() &&
                k1.GetPrivateExponent() == k2.GetPrivateExponent();
}


inline bool IsSamePublicKey(const RSA::PublicKey &k1,
                            const RSA::PublicKey &k2) {
        return k1.GetModulus() == k2.GetModulus() &&
                k1.GetPublicExponent() == k2.GetPublicExponent();
}


class RSAKeyPair {
public:
        RSAKeyPair(bool create=true);
        RSA::PrivateKey pri_;
        RSA::PublicKey pub_;
        bool operator==(const RSAKeyPair &other) const;
        bool operator!=(const RSAKeyPair &other) const;
        bool Verify() const;
};


/**
 * Encode key into string
 * 
 * @params[in]  key     key to encode
 * @params[out] result  output
 *
 */
void EncodeKey(const RSAFunction &key, std::string *result);


void DecodeKey(RSAFunction *key, const std::string &result);


void RSAEncrypt(const RSA::PublicKey &pub_key, const std::string &plain,
                std::string *cipher);


void RSADecrypt(const RSA::PrivateKey &pri_key, const std::string &cipher,
                std::string *recovered);

};

#endif
