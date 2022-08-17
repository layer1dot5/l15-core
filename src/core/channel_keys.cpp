
#include "common.hpp"
#include "channel_keys.hpp"
#include "hash_helper.hpp"

namespace l15::core {

const CSHA256 TAPTWEAK_HASH = PrecalculatedTaggedHash("TapTweak");


void ChannelKeys::CachePubkey()
{
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(m_ctx, &pubkey, m_local_sk.data())) {
        throw WrongKeyError();
    }

    secp256k1_xonly_pubkey xonly_pubkey;
    if (!secp256k1_xonly_pubkey_from_pubkey(m_ctx, &xonly_pubkey, NULL, &pubkey)) {
        throw WrongKeyError();
    }

    if (!secp256k1_xonly_pubkey_serialize(m_ctx, m_local_pk.data(), &xonly_pubkey)) {
        throw WrongKeyError();
    }

    m_pubkey_agg = m_local_pk;
}

//void ChannelKeys::AggregateMuSigPubKey(const std::vector<xonly_pubkey>& pubkeys)
//{
//    size_t n = pubkeys.size() + 1;
//    secp256k1_xonly_pubkey* xonly_pubkeys[n];
//    secp256k1_xonly_pubkey xonly_pubkey_buf[n];
//
//    for (size_t i = 0; i < n-1; ++i) {
//        xonly_pubkeys[i] = &xonly_pubkey_buf[i];
//        if (!secp256k1_xonly_pubkey_parse(m_ctx, xonly_pubkeys[i], pubkeys[i].data())) {
//            throw WrongKeyError();
//        }
//    }
//    xonly_pubkeys[n-1] = &xonly_pubkey_buf[n-1];
//    if (!secp256k1_xonly_pubkey_parse(m_ctx, xonly_pubkeys[n-1], GetLocalPubKey().data())) {
//        throw WrongKeyError();
//    }
//
//    if (!secp256k1_xonly_sort(m_ctx, (const secp256k1_xonly_pubkey **)xonly_pubkeys, n)) {
//        throw WrongKeyError();
//    }
//
//    std::vector<bytevector> outpubkeys;
//    outpubkeys.resize(n);
//    for (size_t i = 0; i < n; ++i) {
//        outpubkeys[i].resize(32);
//        secp256k1_xonly_pubkey_serialize(m_ctx, outpubkeys[i].data(), xonly_pubkeys[i]);
//        std::clog << "Key " << i << ": " << HexStr(outpubkeys[i]) << std::endl;
//    }
//
//    if (!secp256k1_musig_pubkey_agg(m_ctx, NULL, &m_xonly_pubkey_agg, NULL, xonly_pubkeys, pubkeys.size()+1)) {
//        throw WrongKeyError();
//    }
//
//    std::clog << "Aggregated key: " << HexStr(GetPubKey()) << std::endl;
//
//}


std::pair<xonly_pubkey, uint8_t> ChannelKeys::AddTapTweak(std::optional<uint256>&& merkle_root) const
{
    secp256k1_pubkey out;

    HashWriter hash(TAPTWEAK_HASH);
    hash << Span(GetPubKey());
    if (merkle_root.has_value()) {
        hash << Span(*merkle_root);
    }
    uint256 tweak = hash;

    secp256k1_xonly_pubkey pubkey_agg = m_pubkey_agg.get(m_ctx);

    if (!secp256k1_xonly_pubkey_tweak_add(m_ctx, &out, &pubkey_agg, tweak.data())) {
        throw WrongKeyError();
    }

    int parity = -1;
    std::pair<xonly_pubkey, bool> ret;
    secp256k1_xonly_pubkey out_xonly;

    if (!secp256k1_xonly_pubkey_from_pubkey(m_ctx, &out_xonly, &parity, &out)) {
        throw WrongKeyError();
    }

    ret.first.set(m_ctx, out_xonly);

    assert(parity == 0 || parity == 1);

    ret.second = parity;

    return ret;
}

seckey ChannelKeys::GetStrongRandomKey()
{
    seckey key;
    do {
        GetStrongRandBytes(key);
    } while (!secp256k1_ec_seckey_verify(m_ctx, key.data()));
    return key;
}


bool pubkey_less(const xonly_pubkey &a, const xonly_pubkey &b)
{
    return memcmp(a.data(), b.data(), a.size()) < 0;
}

}