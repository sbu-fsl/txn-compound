/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @file  secnfs.cpp
 * @brief SecureProxy
 */

#include "secure_proxy.h"

namespace secnfs {

SecureProxy::SecureProxy() {}


SecureProxy::SecureProxy(const std::string &name,
                         const RSA::PublicKey &public_key)
        : name_(name), key_(public_key) { }

};
