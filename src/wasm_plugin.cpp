#ifdef WASM_BIND

#include "common.hpp"
#include "channel_keys.hpp"
#include "create_inscription.hpp"

#include <emscripten.h>
#include <emscripten/bind.h>

class ChannelKeysWrap : private l15::core::ChannelKeys {
public:
    ChannelKeysWrap() : ChannelKeys() {}
    explicit ChannelKeysWrap(const std::string& sk) : ChannelKeys(l15::unhex<l15::seckey>(sk)) {}

    ChannelKeysWrap(const ChannelKeysWrap&) = default;
    ChannelKeysWrap(ChannelKeysWrap&&) noexcept = default;

//    std::string GetLocalPrivKey() const
//    { return hex(ChannelKeys::GetLocalPrivKey()); }

    std::string GetLocalPubKey() const
    { return hex(ChannelKeys::GetLocalPubKey()); }

    std::string SignSchnorr(const std::string& data)
    { return hex(ChannelKeys::SignSchnorr(uint256S(data))); }

};

EMSCRIPTEN_BINDINGS(inscribeit) {
        emscripten::class_<l15::inscribeit::CreateInscriptionBuilder>("CreateInscriptionBuilder")
                .constructor<std::string>()
                .function("UTXO", &l15::inscribeit::CreateInscriptionBuilder::UTXO)
                .function("Data", &l15::inscribeit::CreateInscriptionBuilder::Data)
                .function("FeeRate", &l15::inscribeit::CreateInscriptionBuilder::FeeRate)
                .function("PrivKeys", &l15::inscribeit::CreateInscriptionBuilder::PrivKeys)
                .function("Build", &l15::inscribeit::CreateInscriptionBuilder::Build)
                .function("Serialize", &l15::inscribeit::CreateInscriptionBuilder::Serialize)

                .function("IntermediateTaprootPrivKey", &l15::inscribeit::CreateInscriptionBuilder::IntermediateTaprootPrivKey)
        ;

    emscripten::class_<ChannelKeysWrap>("ChannelKeys")
                .constructor<>()
                .constructor<const std::string&>()
                .function("GetLocalPubKey", &ChannelKeysWrap::GetLocalPubKey)
                .function("SignSchnorr", &ChannelKeysWrap::SignSchnorr)
        ;
}
#endif
