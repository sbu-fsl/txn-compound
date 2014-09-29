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
        // Add itself as the first proxy.
        ctx->AddCurrentProxy();

        AutoSeededRandomPool prng;
        ProxyManager& pm = ctx->proxy_manager();

        for (int i = 1; i < nproxy; ++i) {
                char name[64];
                snprintf(name, 64, "proxy-%d", i);

                RSA::PrivateKey pri_key;
                pri_key.GenerateRandomWithKeySize(prng, RSAKeyLength);
                RSA::PublicKey pub_key(pri_key);

                pm.add_proxy(SecureProxy(name, pub_key));
        }
}


secnfs::Context* NewContextWithProxies(int nproxy) {
        Context* ctx = new Context("proxy-0");

        AddProxies(ctx, nproxy);

        return ctx;
}


secnfs_info_t* NewSecnfsInfo(int nproxy) {
        secnfs_info_t* info = new secnfs_info_t();
        Context* context = NewContextWithProxies(nproxy);

        info->secnfs_name = strdup(context->name().c_str());

        info->context_size = sizeof(*context);
        info->context = context;

        return info;
}

};
