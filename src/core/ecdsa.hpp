#pragma once

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

#include "random.h"

#include "common.hpp"
#include "schnorr.hpp"

namespace l15::core {

class EcdsaKeyPair
{
    const secp256k1_context* m_ctx;
    seckey m_sk;
public:
    EcdsaKeyPair() : m_ctx(core::SchnorrKeyPair::GetStaticSecp256k1Context()), m_sk(core::SchnorrKeyPair::GetStrongRandomKey(m_ctx)) {}
    explicit EcdsaKeyPair(seckey sk): m_ctx(core::SchnorrKeyPair::GetStaticSecp256k1Context()), m_sk(std::move(sk)) {}
    explicit EcdsaKeyPair(const secp256k1_context* secp256k1_ctx, seckey sk): m_ctx(secp256k1_ctx), m_sk(std::move(sk)) {}

    EcdsaKeyPair(const EcdsaKeyPair&) = default;
    EcdsaKeyPair(EcdsaKeyPair &&old) noexcept: m_ctx(old.m_ctx), m_sk(std::move(old.m_sk)) {}

    EcdsaKeyPair& operator= (const EcdsaKeyPair&) = default;
    EcdsaKeyPair& operator= (EcdsaKeyPair &&old) noexcept
    { m_ctx = old.m_ctx; m_sk = std::move(old.m_sk); return *this; }

    const seckey& GetPrivKey() const { return m_sk; }
    compressed_pubkey GetPubKey() const;

    bytevector SignTxHash(const uint256 &sighash, unsigned char sighashtype) const;
    bytevector SignSegwitV0Tx(const CMutableTransaction &tx, uint32_t nin, std::vector<CTxOut> spent_outputs, const CScript& pubkeyscript, const int hashtype) const;
};

}
