/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @file  secnfs.cpp
 * @brief SecureProxy
 */

#include <fstream>

#include <glog/logging.h>

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


bool ProxyManager::Load(const std::string& config_file) {
        std::ifstream input(config_file.c_str());
        ProxyList plist;

        if (!plist.ParseFromIstream(&input)) {
                LOG(ERROR) << "cannot load ProxyManager from " << config_file;
                return false;
        }

        SetProxyList(plist);

        return true;
}


void ProxyManager::SetProxyList(const ProxyList& plist) {
        proxies_.resize(plist.proxies_size());
        for (int i = 0; i < plist.proxies_size(); ++i) {
                const ProxyEntry& pe = plist.proxies(i);
                proxies_[i].set_name(pe.name());
                proxies_[i].set_key(pe.key());
        }
}


SecureProxy* ProxyManager::Find(const std::string& nm) {
        for (size_t i = 0; i < proxies_.size(); ++i) {
                if (proxies_[i].name() == nm) {
                        return &proxies_[i];
                }
        }

        return NULL;
}

};
