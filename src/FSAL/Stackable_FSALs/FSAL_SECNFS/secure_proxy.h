/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @file  secnfs.h
 * @brief SecureProxy
 */

#ifndef H_SECNFS_PROXY
#define H_SECNFS_PROXY

#include <string>

#include <cryptopp/rsa.h>
using CryptoPP::RSA;

namespace secnfs {

/**
 * A SecureProxy class that contains public information of a proxy.
 *
 * SecureProxy information should be maintained by a public-key server.
 */
class SecureProxy {
public:
        SecureProxy(const std::string &name, RSA::PrivateKey &private_key);
        std::string name_;
        RSA::PublicKey key_;
};

};


#endif
