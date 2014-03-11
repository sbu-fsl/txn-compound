/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @file  secnfs.h
 * @brief Encrypt and decrypt data
 */

#ifndef H_SECNFS_CONTEXT
#define H_SECNFS_CONTEXT

#include "secure_proxy.h"

#include <vector>
#include <string>

#include <cryptopp/rsa.h>
using CryptoPP::RSA;

namespace secnfs {

/**
 * Encode key into string
 * 
 * @params[in]  key     key to encode
 * @params[out] result  output
 *
 */
void EncodeKey(const ASN1Object &key, std::string *result);


void DecodeKey(ASN1Object *key, const std::string &result);


/**
 * Secure Proxy Context.
 */
class Context {
public:
        Context(bool create = false);
        ~Context();

        std::string name_;              /*!< name of current proxy */
        RSA::PrivateKey *psk_pri_;      /*!< Proxy Sign Key (private) */
        RSA::PublicKey *psk_pub_;       /*!< Proxy Sign Key (private) */

        // We use vector because we do not expect a lot of proxies.
        std::vector<SecureProxy> proxies_;      /*!< list of proxies */
        void AddProxy(const SecureProxy &proxy);

        void Load(const std::string &filename);
        void Unload(const std::string &filename);
};

};

#endif
