#include "script/interpreter.h"
#include "secp256k1.h"

#include "allocators/secure.h"
#include "secp256k1_schnorrsig.h"

#include "common.hpp"
#include "channel_keys.hpp"
#include "hash_helper.hpp"
#include "script_merkle_tree.hpp"

#include <mutex>
#include <atomic>

namespace l15::core {

namespace {

std::atomic<volatile secp256k1_context*> ctx = nullptr;
std::mutex ctx_mutex;

}

secp256k1_xonly_pubkey ChannelKeys::unspendable_base;

secp256k1_context *ChannelKeys::GetStaticSecp256k1Context()
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

            bytevector unspend_key_bytes = unhex<bytevector>("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0");
            secp256k1_pubkey unspend_pubkey;
            if (!secp256k1_ec_pubkey_parse(res, &unspend_pubkey, unspend_key_bytes.data(), unspend_key_bytes.size()))
            {
                throw WrongKeyError();
            }
            if (!secp256k1_xonly_pubkey_from_pubkey(res, &unspendable_base, NULL, &unspend_pubkey))
            {
                throw WrongKeyError();
            }
        }
    }
    return res;
}

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


std::pair<xonly_pubkey, uint8_t> ChannelKeys::AddTapTweak(const std::optional<uint256>& merkle_root)
{
    HashWriter hash(TAPTWEAK_HASH);
    hash << Span(GetPubKey());
    if (merkle_root.has_value()) {
        hash << *merkle_root;
    }
    uint256 tweak = hash;

    seckey tweaked_sk;
    secp256k1_xonly_pubkey tweaked_pk;
    secp256k1_keypair keypair;
    int parity = -1;

    try {
        if (!secp256k1_keypair_create(Secp256k1Context(), &keypair, m_local_sk.data())) {
            throw WrongKeyError();
        }

        if (!secp256k1_keypair_xonly_tweak_add(Secp256k1Context(), &keypair, tweak.data())) {
            throw SignatureError("Tweak error");
        }

        if (!secp256k1_keypair_sec(Secp256k1Context(), tweaked_sk.data(), &keypair)) {
            throw KeyError();
        }

        if (!secp256k1_keypair_xonly_pub(Secp256k1Context(), &tweaked_pk, &parity, &keypair)) {
            throw KeyError();
        }

        memory_cleanse(&keypair, sizeof(keypair));
    }
    catch(...) {
        memory_cleanse(&keypair, sizeof(keypair));
        std::rethrow_exception(std::current_exception());
    }

    m_local_sk = move(tweaked_sk);
    m_local_pk.set(m_ctx, tweaked_pk);
    m_pubkey_agg = m_local_pk;

    return std::make_pair(GetPubKey(), static_cast<bool>(parity));
}

std::pair<ChannelKeys, uint8_t> ChannelKeys::NewKeyAddTapTweak(const std::optional<uint256>& merkle_root) const
{
    HashWriter hash(TAPTWEAK_HASH);
    hash << Span(GetPubKey());
    if (merkle_root.has_value()) {
        hash << *merkle_root;
    }
    uint256 tweak = hash;

    seckey tweaked_sk;
    secp256k1_xonly_pubkey tweaked_pk;
    secp256k1_keypair keypair;
    int parity = -1;
    try {
        if (!secp256k1_keypair_create(Secp256k1Context(), &keypair, m_local_sk.data())) {
            throw WrongKeyError();
        }

        if (!secp256k1_keypair_xonly_tweak_add(Secp256k1Context(), &keypair, tweak.data())) {
            throw SignatureError("Tweak error");
        }

        if (!secp256k1_keypair_sec(Secp256k1Context(), tweaked_sk.data(), &keypair)) {
            throw KeyError();
        }

        if (!secp256k1_keypair_xonly_pub(Secp256k1Context(), &tweaked_pk, &parity, &keypair)) {
            throw KeyError();
        }
        memory_cleanse(&keypair, sizeof(keypair));
    }
    catch (...) {
        memory_cleanse(&keypair, sizeof(keypair));
        std::rethrow_exception(std::current_exception());
    }

    ChannelKeys tweaked_key(move(tweaked_sk));
    return std::make_pair(move(tweaked_key), static_cast<bool>(parity));
}

seckey ChannelKeys::GetStrongRandomKey(const secp256k1_context* ctx)
{
    seckey key;
    do {
        GetStrongRandBytes(key);
    } while (!secp256k1_ec_seckey_verify(ctx, key.data()));
    return key;
}


xonly_pubkey ChannelKeys::CreateUnspendablePubKey(const seckey &random_factor)
{
    const secp256k1_context* ctx = GetStaticSecp256k1Context();
    secp256k1_pubkey unspendable;

    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &unspendable, &unspendable_base, random_factor.data())) {
        throw KeyError();
    }
    secp256k1_xonly_pubkey out_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &out_xonly, NULL, &unspendable)) {
        throw KeyError();
    }

    return xonly_pubkey(ctx, out_xonly);
}


std::pair<xonly_pubkey, uint8_t> ChannelKeys::AddTapTweak(const xonly_pubkey &pk, const std::optional<uint256>& merkle_root)
{
    const secp256k1_context* ctx = GetStaticSecp256k1Context();

    secp256k1_pubkey out;

    HashWriter hash(TAPTWEAK_HASH);
    hash << Span(pk);
    if (merkle_root.has_value())
        hash << *merkle_root;
    uint256 tweak = hash;

    secp256k1_xonly_pubkey pubkey = pk.get(ctx);

    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &out, &pubkey, tweak.data())) {
        throw SignatureError("Tweak error");
    }

    int parity = -1;
    std::pair<xonly_pubkey, bool> ret;
    secp256k1_xonly_pubkey out_xonly;

    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &out_xonly, &parity, &out)) {
        throw KeyError();
    }

    ret.first.set(ctx, out_xonly);

    assert(parity == 0 || parity == 1);

    ret.second = parity;

    return ret;
}


signature ChannelKeys::SignSchnorr(const uint256& data) const
{
    signature sig;
    seckey aux = GetStrongRandomKey();

    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(Secp256k1Context(), &keypair, m_local_sk.data())) throw KeyError();
//        if (merkle_root) {
//            secp256k1_xonly_pubkey pubkey;
//            if (!secp256k1_keypair_xonly_pub(secp256k1_context_sign, &pubkey, nullptr, &keypair)) return false;
//            unsigned char pubkey_bytes[32];
//            if (!secp256k1_xonly_pubkey_serialize(secp256k1_context_sign, pubkey_bytes, &pubkey)) return false;
//            uint256 tweak = XOnlyPubKey(pubkey_bytes).ComputeTapTweakHash(merkle_root->IsNull() ? nullptr : merkle_root);
//            if (!secp256k1_keypair_xonly_tweak_add(GetVerifyContext(), &keypair, tweak.data())) return false;
//        }
    bool ret = secp256k1_schnorrsig_sign32(Secp256k1Context(), sig.data(), data.data(), &keypair, aux.data());
    if (ret) {
        // Additional verification step to prevent using a potentially corrupted signature
        secp256k1_xonly_pubkey pubkey_verify;
        ret = secp256k1_keypair_xonly_pub(Secp256k1Context(), &pubkey_verify, nullptr, &keypair);
        ret &= secp256k1_schnorrsig_verify(Secp256k1Context(), sig.data(), data.data(), data.size(), &pubkey_verify);
    }
    if (!ret) memory_cleanse(sig.data(), sig.size());
    memory_cleanse(&keypair, sizeof(keypair));

    if (!ret) throw SignatureError("Signing error");

    return sig;
}

signature ChannelKeys::SignTaprootTx(const CMutableTransaction &tx, uint32_t nin, std::vector<CTxOut> spent_outputs, const CScript& spend_script, int hashtype) const
{
    uint256 sighash;
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::move(spent_outputs), true);

    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false; // Only support annex-less signing for now.

    if(!spend_script.empty()) {
        execdata.m_codeseparator_pos_init = true;
        execdata.m_codeseparator_pos = 0xFFFFFFFF; // Only support non-OP_CODESEPARATOR BIP342 signing for now.
        execdata.m_tapleaf_hash_init = true;
        execdata.m_tapleaf_hash = TapLeafHash(spend_script);
    }

    if(!SignatureHashSchnorr(sighash, execdata, tx, nin, hashtype, execdata.m_tapleaf_hash_init ? SigVersion::TAPSCRIPT : SigVersion::TAPROOT, txdata, MissingDataBehavior::FAIL)) {
        throw SignatureError("Sighash generation error");
    }

    signature sig = SignSchnorr(sighash);

    if(hashtype) {
        sig.push_back(hashtype);
    }

    return sig;
}

bool pubkey_less(const xonly_pubkey &a, const xonly_pubkey &b)
{
    return memcmp(a.data(), b.data(), a.size()) < 0;
}

}