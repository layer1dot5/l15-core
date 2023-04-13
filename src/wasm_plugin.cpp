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


EMSCRIPTEN_BINDINGS(inscribeit) {

    emscripten::function("InitSecp256k1", &InitSecp256k1);

    emscripten::class_<l15::inscribeit::CreateInscriptionBuilder>("CreateInscriptionBuilder")
            .constructor<std::string>()
            .property(l15::inscribeit::ContractBuilder::name_version.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetProtocolVersion)
            .property(l15::inscribeit::CreateInscriptionBuilder::name_utxo_txid.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetUtxoTxId, &l15::inscribeit::CreateInscriptionBuilder::SetUtxoTxId)
            .property(l15::inscribeit::CreateInscriptionBuilder::name_utxo_nout.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetUtxoNOut, &l15::inscribeit::CreateInscriptionBuilder::SetUtxoNOut)
            .property(l15::inscribeit::CreateInscriptionBuilder::name_utxo_amount.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetUtxoAmount, &l15::inscribeit::CreateInscriptionBuilder::SetUtxoAmount)
            .property(l15::inscribeit::ContractBuilder::name_mining_fee_rate.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetMiningFeeRate, &l15::inscribeit::CreateInscriptionBuilder::SetMiningFeeRate)
            .property(l15::inscribeit::CreateInscriptionBuilder::name_content_type.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetContentType, &l15::inscribeit::CreateInscriptionBuilder::SetContentType)
            .property(l15::inscribeit::CreateInscriptionBuilder::name_content.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetContent, &l15::inscribeit::CreateInscriptionBuilder::SetContent)
            .property(l15::inscribeit::CreateInscriptionBuilder::name_destination_pk.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetDestinationPubKey, &l15::inscribeit::CreateInscriptionBuilder::SetDestinationPubKey)
            .property(l15::inscribeit::CreateInscriptionBuilder::name_utxo_pk.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetUtxoPubKey)
            .property(l15::inscribeit::CreateInscriptionBuilder::name_utxo_sig.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetUtxoSig)
            .property(l15::inscribeit::CreateInscriptionBuilder::name_inscribe_script_pk.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetInscribeScriptPubKey)
            .property(l15::inscribeit::CreateInscriptionBuilder::name_inscribe_sig.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetInscribeScriptSig)
            .property(l15::inscribeit::CreateInscriptionBuilder::name_inscribe_int_pk.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetInscribeInternaltPubKey)

            .function("Sign", &l15::inscribeit::CreateInscriptionBuilder::Sign)
            .function("Serialize", &l15::inscribeit::CreateInscriptionBuilder::Serialize)

            .property("intermediate_taproot_sk", &l15::inscribeit::CreateInscriptionBuilder::IntermediateTaprootPrivKey)
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
            .property(l15::inscribeit::ContractBuilder::name_version.c_str(), &l15::inscribeit::SwapInscriptionBuilder::GetProtocolVersion)
            .property(l15::inscribeit::SwapInscriptionBuilder::name_mining_fee_rate.c_str(), &l15::inscribeit::SwapInscriptionBuilder::GetMiningFeeRate, &l15::inscribeit::SwapInscriptionBuilder::SetMiningFeeRate)
            .property(l15::inscribeit::SwapInscriptionBuilder::name_ord_commit_mining_fee_rate.c_str(), &l15::inscribeit::SwapInscriptionBuilder::GetOrdCommitMiningFeeRate, &l15::inscribeit::SwapInscriptionBuilder::SetOrdCommitMiningFeeRate)
            .property(l15::inscribeit::SwapInscriptionBuilder::name_swap_script_pk_A.c_str(), &l15::inscribeit::SwapInscriptionBuilder::GetSwapScriptPubKeyA, &l15::inscribeit::SwapInscriptionBuilder::SetSwapScriptPubKeyA)
            .property(l15::inscribeit::SwapInscriptionBuilder::name_swap_script_pk_B.c_str(), &l15::inscribeit::SwapInscriptionBuilder::GetSwapScriptPubKeyB, &l15::inscribeit::SwapInscriptionBuilder::SetSwapScriptPubKeyB)
            .property(l15::inscribeit::SwapInscriptionBuilder::name_swap_script_pk_M.c_str(), &l15::inscribeit::SwapInscriptionBuilder::GetSwapScriptPubKeyM, &l15::inscribeit::SwapInscriptionBuilder::SetSwapScriptPubKeyM)
            .property(l15::inscribeit::SwapInscriptionBuilder::name_ord_txid.c_str(), &l15::inscribeit::SwapInscriptionBuilder::GetOrdUtxoTxId, &l15::inscribeit::SwapInscriptionBuilder::SetOrdUtxoTxId)
            .property(l15::inscribeit::SwapInscriptionBuilder::name_ord_nout.c_str(), &l15::inscribeit::SwapInscriptionBuilder::GetOrdUtxoNOut, &l15::inscribeit::SwapInscriptionBuilder::SetOrdUtxoNOut)
            .property(l15::inscribeit::SwapInscriptionBuilder::name_ord_amount.c_str(), &l15::inscribeit::SwapInscriptionBuilder::GetOrdUtxoAmount, &l15::inscribeit::SwapInscriptionBuilder::SetOrdUtxoAmount)
            .property(l15::inscribeit::SwapInscriptionBuilder::name_funds_txid.c_str(), &l15::inscribeit::SwapInscriptionBuilder::GetFundsUtxoTxId, &l15::inscribeit::SwapInscriptionBuilder::SetFundsUtxoTxId)
            .property(l15::inscribeit::SwapInscriptionBuilder::name_funds_nout.c_str(), &l15::inscribeit::SwapInscriptionBuilder::GetFundsUtxoNOut, &l15::inscribeit::SwapInscriptionBuilder::SetFundsUtxoNOut)
            .property(l15::inscribeit::SwapInscriptionBuilder::name_funds_amount.c_str(), &l15::inscribeit::SwapInscriptionBuilder::GetFundsUtxoAmount, &l15::inscribeit::SwapInscriptionBuilder::SetFundsUtxoAmount)

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

