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

static void AddProxies(Context *ctx, int nproxy, AutoSeededRandomPool *prng) {
        for (int i = 0; i < nproxy; ++i) {
                char name[64];
                snprintf(name, 64, "proxy-%u", prng->GenerateWord32());

                RSA::PrivateKey pri_key;
                pri_key.GenerateRandomWithKeySize(*prng, RSAKeyLength);

                ctx->AddProxy(SecureProxy(name, pri_key));
        }
}


secnfs::Context *NewContextWithProxies(int nproxy) {
        AutoSeededRandomPool prng;
        secnfs_info_t info;

        Context *ctx = new Context(&info);
        
        AddProxies(ctx, nproxy, &prng);

        //snprintf(info.secnfs_name, MAXPATHLEN,
                 //ctx->proxies_[0].name_.c_str());

        ctx->set_name(ctx->proxies_[0].name_);

        return ctx;
}


secnfs_info_t *NewSecnfsInfo(int nproxy) {
        secnfs_info_t *info = new secnfs_info_t();
        Context *context = NewContextWithProxies(nproxy);

        strncpy(info->secnfs_name, context->name_.c_str(), MAXPATHLEN);

        info->context_size = sizeof(*context);
        info->context = context;

        return info;
}

};
