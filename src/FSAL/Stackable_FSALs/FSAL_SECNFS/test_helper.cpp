/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#include "test_helper.h"

#include <stdio.h>

namespace secnfs_test {

static void AddProxies(int n, AutoSeededRandomPool *prng) {
        for (int i = 0; i < nproxy; ++i) {
                char name[64];
                snprintf(name, 64, "proxy-%u", prng->GenerateWord32());

                RSA::PrivateKey pri_key;
                pri_key.GenerateRandomWithKeySize(*prng, RSAKeyLength);

                ctx.AddProxy(SecureProxy(name, pri_key));
        }
}


secnfs::Context *NewContextWithProxies(int nproxy) {
        AutoSeededRandomPool prng;
        secnfs_info_t info;

        snprintf(info.secnfs_name, MAXPATHLEN, "context-%u",
                 prng.GenerateWord32());

        Context ctx(&info);
        
        AddProxies(nproxy, &prng);
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
