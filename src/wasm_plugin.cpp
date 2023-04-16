#ifdef WASM_MODULE

#include "random.h"

#include "common.hpp"
#include "channel_keys.hpp"
#include "create_inscription.hpp"
#include "swap_inscription.hpp"

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

    std::string GetLocalPrivKey() const
    { return l15::hex(l15::core::ChannelKeys::GetLocalPrivKey()); }

    std::string GetLocalPubKey() const
    { return l15::hex(l15::core::ChannelKeys::GetLocalPubKey()); }

    std::string SignSchnorr(std::string data) const
    { return l15::hex(l15::core::ChannelKeys::SignSchnorr(uint256S(data))); }
};

void InitSecp256k1() {
    GetSecp256k1();
}

std::string GetExceptionMessage(intptr_t exceptionPtr) {
  return std::string(reinterpret_cast<std::exception *>(exceptionPtr)->what());
}


EMSCRIPTEN_BINDINGS(inscribeit) {

    emscripten::function("InitSecp256k1", &InitSecp256k1);
    emscripten::function("getExceptionMessage", &GetExceptionMessage);

    emscripten::class_<l15::inscribeit::CreateInscriptionBuilder>("CreateInscriptionBuilder")
            .constructor<std::string>()
            .function("UTXO", &l15::inscribeit::CreateInscriptionBuilder::UTXO)
            .function("Data", &l15::inscribeit::CreateInscriptionBuilder::Data)
            .function("MiningFeeRate", &l15::inscribeit::CreateInscriptionBuilder::FeeRate)
            .function("DestinationPubKey", &l15::inscribeit::CreateInscriptionBuilder::Destination)
            .function("Sign", &l15::inscribeit::CreateInscriptionBuilder::Sign)
            .function("Serialize", &l15::inscribeit::CreateInscriptionBuilder::Serialize)

            .function("getIntermediateTaprootSK", &l15::inscribeit::CreateInscriptionBuilder::IntermediateTaprootPrivKey)
            ;

    emscripten::enum_<l15::inscribeit::SwapInscriptionBuilder::SwapPhase>("SwapPhase")
            .value("ORD_TERMS", l15::inscribeit::SwapInscriptionBuilder::OrdTerms)
            .value("ORD_COMMIT_SIG", l15::inscribeit::SwapInscriptionBuilder::OrdCommitSig)
            .value("FUNDS_TERMS", l15::inscribeit::SwapInscriptionBuilder::FundsTerms)
            .value("FUNDS_COMMIT_SIG", l15::inscribeit::SwapInscriptionBuilder::FundsCommitSig)
            .value("ORD_PAYOFF_TERMS", l15::inscribeit::SwapInscriptionBuilder::MarketPayoffTerms)
            .value("ORD_PAYOFF_SIG", l15::inscribeit::SwapInscriptionBuilder::MarketPayoffSig)
            .value("ORD_SWAP_SIG", l15::inscribeit::SwapInscriptionBuilder::OrdSwapSig)
            .value("FUNDS_SWAP_SIG", l15::inscribeit::SwapInscriptionBuilder::FundsSwapSig)
            .value("MARKET_SWAP_SIG", l15::inscribeit::SwapInscriptionBuilder::MarketSwapSig)
            ;

    emscripten::class_<l15::inscribeit::SwapInscriptionBuilder>("SwapInscriptionBuilder")
            .constructor<std::string, std::string, std::string>()

            .function("OrdUTXO", &l15::inscribeit::SwapInscriptionBuilder::OrdUTXO)
            .function("FundsUTXO", &l15::inscribeit::SwapInscriptionBuilder::FundsUTXO)

            .function("SwapPubKeyA", &l15::inscribeit::SwapInscriptionBuilder::SetSwapScriptPubKeyA)
            .function("SwapPubKeyB", &l15::inscribeit::SwapInscriptionBuilder::SetSwapScriptPubKeyB)

            .function("CheckContractTerms", &l15::inscribeit::SwapInscriptionBuilder::CheckContractTerms)

            .function("SignOrdCommitment", &l15::inscribeit::SwapInscriptionBuilder::SignOrdCommitment)
            .function("SignOrdPayBack", &l15::inscribeit::SwapInscriptionBuilder::SignOrdPayBack)
            .function("SignOrdSwap", &l15::inscribeit::SwapInscriptionBuilder::SignOrdSwap)
            .function("SignFundsCommitment", &l15::inscribeit::SwapInscriptionBuilder::SignFundsCommitment)
            .function("SignFundsPayBackt", &l15::inscribeit::SwapInscriptionBuilder::SignFundsPayBack)
            .function("SignFundsSwap", &l15::inscribeit::SwapInscriptionBuilder::SignFundsSwap)

            .function("Serialize", &l15::inscribeit::SwapInscriptionBuilder::Serialize)
            .function("Deserialize", &l15::inscribeit::SwapInscriptionBuilder::Deserialize)
            ;

    emscripten::class_<ChannelKeysWasm>("ChannelKeys")
            .constructor()
            .constructor<std::string>()
            .function("GetLocalPrivKey", &ChannelKeysWasm::GetLocalPrivKey)
            .function("GetLocalPubKey", &ChannelKeysWasm::GetLocalPubKey)
            .function("SignSchnorr", &ChannelKeysWasm::SignSchnorr)
        ;
}
#endif

