/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @file  secnfs.h
 * @brief Encrypt and decrypt data
 */

#ifndef H_SECNFS_CONTEXT
#define H_SECNFS_CONTEXT

#include "secnfs_lib.h"
#include "secure_proxy.h"

#include <vector>
#include <string>

#include <cryptopp/rsa.h>
using CryptoPP::RSA;

namespace secnfs {

// FIXME make the file configurable
const std::string SecNFSContextPath  = "/etc/secnfs-context.conf";

/**
 * Secure Proxy Context.
 */
class Context {
public:
        Context(bool create = false);
        ~Context();

        std::string name_;              /*!< name of current proxy */
        RSAKeyPair key_pair_;           /*!< RSA key pair */

        // We use vector because we do not expect a lot of proxies.
        std::vector<SecureProxy> proxies_;      /*!< list of proxies */
        void AddProxy(const SecureProxy &proxy);

        void Load(const std::string &filename);
        void Unload(const std::string &filename);

        void GenerateKeyFile(secnfs_key_t *key, secnfs_key_t *iv, KeyFile *kf);
};

};

#endif
