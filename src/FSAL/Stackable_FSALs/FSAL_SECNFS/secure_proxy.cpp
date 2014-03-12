/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @file  secnfs.cpp
 * @brief SecureProxy
 */

#include "secure_proxy.h"

namespace secnfs {

SecureProxy::SecureProxy() {}


SecureProxy::SecureProxy(const std::string &name, RSA::PrivateKey &private_key)
        : name_(name), key_(private_key) { }

};
