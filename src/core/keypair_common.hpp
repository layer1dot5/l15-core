#pragma once

#include "secp256k1.h"
#include "common.hpp"

namespace l15::core {


struct KeyPairBase {
    static secp256k1_context* GetStaticSecp256k1Context();
    static void SetStaticSecp256k1ContextInt(secp256k1_context* ctx);
    static seckey GetStrongRandomKey(const secp256k1_context* ctx = GetStaticSecp256k1Context());
};

}
