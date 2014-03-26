/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#include "test_helper.h"
#include "secnfs_lib.h"

#include <stdio.h>

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

using namespace secnfs;

namespace secnfs_test {

static void AddProxies(Context* ctx, int nproxy) {
        AutoSeededRandomPool prng;
        ProxyManager* pm = ctx->proxy_manager();

        // Add itself as the first proxy.
        pm->add_proxy(SecureProxy(ctx->name(), ctx->pub_key()));

        for (int i = 1; i < nproxy; ++i) {
                char name[64];
                snprintf(name, 64, "proxy-%d", i);

                RSA::PrivateKey pri_key;
                pri_key.GenerateRandomWithKeySize(prng, RSAKeyLength);
                RSA::PublicKey pub_key(pri_key);

                pm->add_proxy(SecureProxy(name, pub_key));
        }
}


secnfs::Context* NewContextWithProxies(int nproxy) {
        secnfs_info_t info;

        strcpy(info.secnfs_name, "proxy-0");

        Context* ctx = new Context(&info);

        AddProxies(ctx, nproxy);

        return ctx;
}


secnfs_info_t* NewSecnfsInfo(int nproxy) {
        secnfs_info_t* info = new secnfs_info_t();
        Context* context = NewContextWithProxies(nproxy);

        strncpy(info->secnfs_name, context->name().c_str(), MAXPATHLEN);

        info->context_size = sizeof(*context);
        info->context = context;

        return info;
}

};
