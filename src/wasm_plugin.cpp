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
            .property(l15::inscribeit::name_version.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetProtocolVersion)
            .property(l15::inscribeit::name_utxo_txid.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetUtxoTxId, &l15::inscribeit::CreateInscriptionBuilder::SetUtxoTxId)
            .property(l15::inscribeit::name_utxo_nout.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetUtxoNOut, &l15::inscribeit::CreateInscriptionBuilder::SetUtxoNOut)
            .property(l15::inscribeit::name_utxo_amount.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetUtxoAmount, &l15::inscribeit::CreateInscriptionBuilder::SetUtxoAmount)
            .property(l15::inscribeit::name_fee_rate.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetFeeRate, &l15::inscribeit::CreateInscriptionBuilder::SetFeeRate)
            .property(l15::inscribeit::name_content_type.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetContentType, &l15::inscribeit::CreateInscriptionBuilder::SetContentType)
            .property(l15::inscribeit::name_content.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetContent, &l15::inscribeit::CreateInscriptionBuilder::SetContent)
            .property(l15::inscribeit::name_destination_pk.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetDestinationPubKey, &l15::inscribeit::CreateInscriptionBuilder::SetDestinationPubKey)
            .property(l15::inscribeit::name_utxo_pk.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetUtxoPubKey)
            .property(l15::inscribeit::name_utxo_sig.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetUtxoSig)
            .property(l15::inscribeit::name_inscribe_script_pk.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetInscribeScriptPubKey)
            .property(l15::inscribeit::name_inscribe_sig.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetInscribeScriptSig)
            .property(l15::inscribeit::name_inscribe_int_pk.c_str(), &l15::inscribeit::CreateInscriptionBuilder::GetInscribeInternaltPubKey)
//                .function("UTXO", &l15::inscribeit::CreateInscriptionBuilder::UTXO)
//                .function("Data", &l15::inscribeit::CreateInscriptionBuilder::Data)
//                .function("FeeRate", &l15::inscribeit::CreateInscriptionBuilder::FeeRate)
//                .function("PrivKeys", &l15::inscribeit::CreateInscriptionBuilder::PrivKeys)
            .function("Sign", &l15::inscribeit::CreateInscriptionBuilder::Sign)
            .function("Serialize", &l15::inscribeit::CreateInscriptionBuilder::Serialize)

            .property("intermediate_taproot_pk", &l15::inscribeit::CreateInscriptionBuilder::IntermediateTaprootPrivKey)
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

