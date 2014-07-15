/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @brief SECNFS library functions and classes.
 * @author Ming Chen <v.mingchen@gmail.com>
 */

#ifndef H_SECNFS_LIB
#define H_SECNFS_LIB

#include <string>
#include <algorithm>
#include <deque>
using std::deque;

#include <cryptopp/rsa.h>
using CryptoPP::RSA;
using CryptoPP::RSAFunction;

#include <google/protobuf/message.h>

#include "secnfs.pb.h"

namespace secnfs {

inline uint64_t round_up(uint64_t n, uint64_t m) {
        assert((m & (m - 1)) == 0);
        return (n + m - 1) & ~(m - 1);
}

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
        RSAKeyPair(const std::string &pub, const std::string &pri);
        RSA::PrivateKey pri_;
        RSA::PublicKey pub_;
        bool operator==(const RSAKeyPair &other) const;
        bool operator!=(const RSAKeyPair &other) const;
        bool Verify() const;
};


class BlockMap {
public:
        BlockMap();
        ~BlockMap();
        uint64_t try_insert(uint64_t offset, uint64_t length);
        void remove(uint64_t offset, uint64_t length);
        void lock() {pthread_mutex_lock(&mutex);};
        void unlock() {pthread_mutex_unlock(&mutex);};
private:
        void insert(uint64_t offset, uint64_t length);
        bool valid(deque<Range>::iterator pos);
        deque<Range> segs;
        pthread_mutex_t mutex; /* protect segs */
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


/**
 * The returned "buf" is owned by the caller, who should free it properly.
 */
bool EncodeMessage(const google::protobuf::Message &msg, void **buf,
                   uint32_t *buf_size, uint32_t align);

bool DecodeMessage(google::protobuf::Message *msg, void *buf,
                   uint32_t buf_size, uint32_t *msg_size);

};

#endif
