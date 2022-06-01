
#include "common.hpp"
#include "channel_keys.hpp"
#include "hash_helper.hpp"

#include "uint256.h"

namespace l15 {

const CSHA256 TAPTWEAK_HASH = PrecalculatedTaggedHash("TapTweak");


void ChannelKeys::MakeNewPrivKey()
{
    m_local_sk.resize(32, 0);
    m_local_pk.resize(32, 0);
    do {
        GetStrongRandBytes(Span(m_local_sk.data(), m_local_sk.size()));
    } while (!secp256k1_ec_seckey_verify(mWallet.GetSecp256k1Context(), m_local_sk.data()));

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(mWallet.GetSecp256k1Context(), &pubkey, GetLocalPrivKey().data())) {
        throw WrongKeyError();
    }

    if (!secp256k1_xonly_pubkey_from_pubkey(mWallet.GetSecp256k1Context(), &m_xonly_pubkey_agg, NULL, &pubkey)) {
        throw WrongKeyError();
    }

    if (!secp256k1_xonly_pubkey_serialize(mWallet.GetSecp256k1Context(), m_local_pk.data(), &m_xonly_pubkey_agg)) {
        throw WrongKeyError();
    }
}



void ChannelKeys::SetRemotePubKeys(const std::vector<bytevector>& pubkeys)
{
    size_t n = pubkeys.size() + 1;
    secp256k1_xonly_pubkey* xonly_pubkeys[n];
    secp256k1_xonly_pubkey xonly_pubkey_buf[n];

    for (size_t i = 0; i < n-1; ++i) {
        xonly_pubkeys[i] = &xonly_pubkey_buf[i];
        if (!secp256k1_xonly_pubkey_parse(mWallet.GetSecp256k1Context(), xonly_pubkeys[i], pubkeys[i].data())) {
            throw WrongKeyError();
        }
    }
    xonly_pubkeys[n-1] = &xonly_pubkey_buf[n-1];
    if (!secp256k1_xonly_pubkey_parse(mWallet.GetSecp256k1Context(), xonly_pubkeys[n-1], GetLocalPubKey().data())) {
        throw WrongKeyError();
    }

    if (!secp256k1_xonly_sort(mWallet.GetSecp256k1Context(), (const secp256k1_xonly_pubkey **)xonly_pubkeys, n)) {
        throw WrongKeyError();
    }

    std::vector<bytevector> outpubkeys;
    outpubkeys.resize(n);
    for (size_t i = 0; i < n; ++i) {
        outpubkeys[i].resize(32);
        secp256k1_xonly_pubkey_serialize(mWallet.GetSecp256k1Context(), outpubkeys[i].data(), xonly_pubkeys[i]);
        std::clog << "Key " << i << ": " << HexStr(outpubkeys[i]) << std::endl;
    }

    if (!secp256k1_musig_pubkey_agg(mWallet.GetSecp256k1Context(), NULL, &m_xonly_pubkey_agg, NULL, xonly_pubkeys, pubkeys.size()+1)) {
        throw WrongKeyError();
    }

    std::clog << "Aggregated key: " << HexStr(GetPubKey()) << std::endl;

}

bytevector ChannelKeys::GetPubKey() const
{
    bytevector res;
    res.resize(32);

    if (!secp256k1_xonly_pubkey_serialize(mWallet.GetSecp256k1Context(), res.data(), &m_xonly_pubkey_agg)) {
        throw WrongKeyError();
    }

    return res;
}

std::pair<bytevector, uint8_t> ChannelKeys::AddTapTweak(std::optional<uint256>&& merkle_root) const
{
    secp256k1_pubkey out;

    HashWriter hash(TAPTWEAK_HASH);
    hash << Span(GetPubKey());
    if (merkle_root.has_value()) {
        hash << Span(*merkle_root);
    }
    uint256 tweak = hash;

    if (!secp256k1_xonly_pubkey_tweak_add(mWallet.GetSecp256k1Context(), &out, &m_xonly_pubkey_agg, tweak.data())) {
        throw WrongKeyError();
    }

    int parity = -1;
    std::pair<bytevector, bool> ret;
    ret.first.resize(32);
    secp256k1_xonly_pubkey out_xonly;

    if (!secp256k1_xonly_pubkey_from_pubkey(mWallet.GetSecp256k1Context(), &out_xonly, &parity, &out)) {
        throw WrongKeyError();
    }

    secp256k1_xonly_pubkey_serialize(mWallet.GetSecp256k1Context(), ret.first.data(), &out_xonly);

    assert(parity == 0 || parity == 1);

    ret.second = parity;

    return ret;
}


bool pubkey_less(const bytevector & a, const bytevector & b)
{
    return uint256(a) < uint256(b);
}
}