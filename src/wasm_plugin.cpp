#ifdef WASM_BIND

#include "random.h"

#include "common.hpp"
#include "channel_keys.hpp"
#include "create_inscription.hpp"

#include <emscripten.h>
#include <emscripten/bind.h>


namespace {

secp256k1_context * CreateSecp256k1() {
    RandomInit();
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    std::vector<unsigned char, secure_allocator<unsigned char>> vseed(32);
    GetRandBytes(vseed);
    int ret = secp256k1_context_randomize(ctx, vseed.data());
    assert(ret);
    return ctx;
}

const secp256k1_context * GetSecp256k1()
{
    static secp256k1_context *ctx = CreateSecp256k1();
    return ctx;
}

}

class ChannelKeysWasm : private l15::core::ChannelKeys {
public:
    ChannelKeysWasm() : l15::core::ChannelKeys(GetSecp256k1()) {}
    explicit ChannelKeysWasm(std::string sk) : l15::core::ChannelKeys(GetSecp256k1(), l15::unhex<l15::seckey>(sk)) {}

    std::string GetLocalPubKey() const
    { return l15::hex(l15::core::ChannelKeys::GetLocalPubKey()); }

    std::string SignSchnorr(std::string data) const
    { return l15::hex(l15::core::ChannelKeys::SignSchnorr(uint256S(data))); }
};

void InitSecp256k1() {
    GetSecp256k1();
}


EMSCRIPTEN_BINDINGS(inscribeit) {

    emscripten::function("InitSecp256k1", &InitSecp256k1);

//        emscripten::class_<l15::inscribeit::CreateInscriptionBuilder>("CreateInscriptionBuilder")
//                .constructor<std::string>()
//                .function("UTXO", &l15::inscribeit::CreateInscriptionBuilder::UTXO)
//                .function("Data", &l15::inscribeit::CreateInscriptionBuilder::Data)
//                .function("FeeRate", &l15::inscribeit::CreateInscriptionBuilder::FeeRate)
//                .function("PrivKeys", &l15::inscribeit::CreateInscriptionBuilder::PrivKeys)
//                .function("Build", &l15::inscribeit::CreateInscriptionBuilder::Build)
//                .function("Serialize", &l15::inscribeit::CreateInscriptionBuilder::Serialize)
//
//                .function("IntermediateTaprootPrivKey", &l15::inscribeit::CreateInscriptionBuilder::IntermediateTaprootPrivKey)
//        ;
//
    emscripten::class_<ChannelKeysWasm>("ChannelKeys")
                .constructor()
                .constructor<std::string>()
                .function("GetLocalPubKey", &ChannelKeysWasm::GetLocalPubKey)
                .function("SignSchnorr", &ChannelKeysWasm::SignSchnorr)
        ;
}
#endif

