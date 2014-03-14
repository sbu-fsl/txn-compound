/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @file  secnfs.h
 * @brief Encrypt and decrypt data
 */

#ifndef H_SECNFS_CONTEXT
#define H_SECNFS_CONTEXT

#include "secnfs.h"
#include "secnfs_lib.h"
#include "secure_proxy.h"
#include "secnfs.pb.h"

#include <vector>
#include <string>

#include <cryptopp/rsa.h>
using CryptoPP::RSA;

#include <tbb/concurrent_hash_map.h>

namespace secnfs {

struct CacheCompare {
        static size_t hash(const std::string &key) {
                 size_t h = 0;
                 for (const char* s = key.c_str(); *s; ++s)
                         h = (h*17)^*s;
                 return h;
        }

        static bool equal(const std::string &k1, const std::string &k2) {
                return k1 == k2;
        }
};

/**
 * Secure Proxy Context.
 */
class Context {
public:
        Context(const secnfs_info_t *secnfs_info, bool create = false);
        ~Context();

        std::string name_;              /*!< name of current proxy */
        RSAKeyPair key_pair_;           /*!< RSA key pair */
        secnfs_info_t *secnfs_info_;

        tbb::concurrent_hash_map<std::string, std::string, CacheCompare> map_;
        typedef tbb::concurrent_hash_map<std::string, std::string,
                                         CacheCompare>::accessor hash_entry;

        // We use vector because we do not expect a lot of proxies.
        std::vector<SecureProxy> proxies_;      /*!< list of proxies */
        void AddProxy(const SecureProxy &proxy);

        void Load(const std::string &filename);
        void Unload(const std::string &filename);

        // key, and iv should be terminated by '\0'.
        void GenerateKeyFile(byte *key, byte *iv, int len, KeyFile *kf);
};

};

#endif
