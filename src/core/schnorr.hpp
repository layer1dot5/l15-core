#pragma once

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

#include "random.h"
#include "interpreter.h"

#include "common.hpp"
#include "common_error.hpp"

#include <optional>

#include "interpreter.h"

namespace l15::core {

class SchnorrKeyPair
{
    const secp256k1_context* m_ctx;
    seckey m_local_sk;
public:
    static secp256k1_context* GetStaticSecp256k1Context();
    static secp256k1_xonly_pubkey unspendable_base;

    explicit SchnorrKeyPair(): m_ctx(GetStaticSecp256k1Context()), m_local_sk(GetStrongRandomKey()) {}
    explicit SchnorrKeyPair(seckey local_sk): m_ctx(GetStaticSecp256k1Context()), m_local_sk(std::move(local_sk)) {}
    explicit SchnorrKeyPair(const secp256k1_context* secp256k1_ctx): m_ctx(secp256k1_ctx), m_local_sk(GetStrongRandomKey()) {}
    explicit SchnorrKeyPair(const secp256k1_context* secp256k1_ctx, seckey local_sk): m_ctx(secp256k1_ctx), m_local_sk(std::move(local_sk)) {}

    SchnorrKeyPair(const SchnorrKeyPair&) = default;
    SchnorrKeyPair(SchnorrKeyPair &&old) noexcept: m_ctx(old.m_ctx), m_local_sk(std::move(old.m_local_sk)) {}

    SchnorrKeyPair& operator=(const SchnorrKeyPair& o) = default;
    SchnorrKeyPair& operator=(SchnorrKeyPair&& old) noexcept = default;

    const secp256k1_context* Secp256k1Context() const noexcept
    { return m_ctx; }

    const seckey& GetPrivKey() const
    { return m_local_sk; }

    xonly_pubkey GetPubKey() const;

    static seckey GetStrongRandomKey(const secp256k1_context* ctx = GetStaticSecp256k1Context()) ;
    static xonly_pubkey CreateUnspendablePubKey(const seckey& random_factor);

    static std::pair<xonly_pubkey, uint8_t> AddTapTweak(const xonly_pubkey& pk, const std::optional<uint256>& merkle_root = {});
    std::pair<xonly_pubkey, uint8_t> AddTapTweak(const std::optional<uint256>& merkle_root = {});

    std::pair<SchnorrKeyPair, uint8_t> NewKeyAddTapTweak(const std::optional<uint256>& merkle_root = {}) const;

    signature SignSchnorr(const uint256& data) const;

    signature SignTaprootTx(const CMutableTransaction &tx, uint32_t nin, std::vector<CTxOut> spent_outputs,
                             const CScript &spend_script, int hashtype = SIGHASH_DEFAULT) const;
};

bool pubkey_less(const xonly_pubkey &, const xonly_pubkey &);

}
