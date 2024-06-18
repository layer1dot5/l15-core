
#include "keypair_common.hpp"
#include "random.h"

#include <mutex>
#include <atomic>


namespace l15::core {

namespace {
    std::atomic<volatile secp256k1_context *> ctx = nullptr;
    std::mutex ctx_mutex;
}

secp256k1_context *KeyPairBase::GetStaticSecp256k1Context()
{
    secp256k1_context* res = const_cast<secp256k1_context *>(ctx.load());
    if (!res) {
        std::lock_guard lock(ctx_mutex);
        if (!ctx) {
            res = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
            std::vector<unsigned char, secure_allocator<unsigned char>> vseed(32);
            RandomInit();
            GetRandBytes(vseed);
            int ret = secp256k1_context_randomize(res, vseed.data());
            assert(ret);
            ctx = res;
        }
    }
    return res;
}

seckey KeyPairBase::GetStrongRandomKey(const secp256k1_context* ctx)
{
    seckey key;
    do {
        GetStrongRandBytes(key);
    } while (!secp256k1_ec_seckey_verify(ctx, key.data()));
    return key;
}


}
