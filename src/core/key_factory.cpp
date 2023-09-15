#include "key_factory.hpp"
#include <algorithm>
#include <limits>

namespace l15::core {

xonly_pubkey PubKeyFactory::MakeKey(uint32_t index)
{
    return MasterKey::DerivePubKey(m_ctx, m_extpk, index);
}

ChannelKeys KeyFactory::MakeKey(uint32_t index)
{
    MasterKey extkey(mMasterKey);
    extkey.DeriveSelf(index);
    return extkey.MakeKey(m_bip86tweak);
}

namespace {

std::optional<uint32_t> LookUpDerivedPubKey(const secp256k1_context* ctx, const ext_pubkey parent, const xonly_pubkey &pk, uint32_t max_limit)
{
    secp256k1_pubkey parent_pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &parent_pubkey, parent.data(), 33)) {
        throw WrongKeyError();
    }

    secp256k1_xonly_pubkey lookup_pubkey = pk.get(ctx);

    uint256 chaincode;
    memcpy(chaincode.begin(), parent.data() + 33, 32);
    uint8_t bip32hash[64];

    for (uint32_t index = 0; index < max_limit; ++index) {
        BIP32Hash(chaincode, index, *parent.data(), parent.data() + 1, bip32hash);

        secp256k1_pubkey pubkey = parent_pubkey;
        if (!secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, bip32hash)) {
            throw KeyError("BIP32 pubkey derivation");
        }

        secp256k1_xonly_pubkey xonlypubkey;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &xonlypubkey, nullptr, &pubkey)) {
            throw KeyError();
        }

        if (memcmp(xonlypubkey.data, lookup_pubkey.data, sizeof(lookup_pubkey.data)) == 0) {
            return index;
        }
    }

    return {};
}

}


bool PubKeyRegistry::LookUpPubKey(const xonly_pubkey &pk, uint32_t index_limit) const
{
    auto it = m_single_keys.find(pk);
    if (it != m_single_keys.cend())
        return true;

    for (const ext_pubkey& parent: m_extkeys) {
        auto r = LookUpDerivedPubKey(m_ctx, parent, pk, index_limit);
        if (r.has_value())
            return true;
    }
    return false;
}

std::optional<ChannelKeys> KeyRegistry::LookUpPubKey(const xonly_pubkey &pk, uint32_t index_limit) const
{
    auto key_it = m_single_keys.find(pk);
    if (key_it != m_single_keys.end())
        return key_it->second;

    for (const auto& parent: m_extkeys) {
        for (uint32_t index = 0; index < index_limit; ++index) {
            std::array<uint32_t, 1> idx = {index};
            ChannelKeys keypair = parent.Derive(idx, m_bip86 ? FORCE : SUPPRESS);
            if (keypair.GetLocalPubKey() == pk)
                return keypair;
        }
    }

    return {};
}


} // l15::core