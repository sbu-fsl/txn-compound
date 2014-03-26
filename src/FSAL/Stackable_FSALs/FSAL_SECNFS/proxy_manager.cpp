/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @file  secnfs.cpp
 * @brief SecureProxy
 */

#include <fstream>

#include "proxy_manager.h"
#include "secnfs_lib.h"

namespace secnfs {

SecureProxy::SecureProxy() {}


SecureProxy::SecureProxy(const std::string& name,
                         const RSA::PublicKey& public_key)
                : name_(name), key_(public_key) { }


SecureProxy::SecureProxy(const ProxyEntry& pe) : name_(pe.name()) {
        set_key(pe.key());
}


void SecureProxy::set_key(const std::string& key_str) {
        DecodeKey(&key_, key_str);
}


ProxyManager::ProxyManager(const ProxyList& plist) {
        SetProxyList(plist);
}


ProxyManager::ProxyManager(const std::string& config_file) {
        Load(config_file);
}


void ProxyManager::Load(const std::string& config_file) {
        std::ifstream input(config_file.c_str());
        ProxyList plist;

        assert(plist.ParseFromIstream(&input));

        SetProxyList(plist);
}


void ProxyManager::SetProxyList(const ProxyList& plist) {
        proxies_.resize(plist.proxies_size());
        for (int i = 0; i < plist.proxies_size(); ++i) {
                const ProxyEntry& pe = plist.proxies(i);
                proxies_[i].set_name(pe.name());
                proxies_[i].set_key(pe.key());
        }
}


};
