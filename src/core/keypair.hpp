#pragma once

#include "utils.hpp"
#include "schnorr.hpp"
#include "ecdsa.hpp"
#include "master_key.hpp"

namespace l15::core {

class KeyPair
{
    const secp256k1_context* m_ctx;
    seckey m_sk;
public:

    KeyPair(const secp256k1_context* ctx, seckey sk) : m_ctx(ctx), m_sk(move(sk)) {}
    explicit KeyPair(seckey sk) : KeyPair(core::SchnorrKeyPair::GetStaticSecp256k1Context(), move(sk)) {}
    KeyPair() : m_ctx(core::SchnorrKeyPair::GetStaticSecp256k1Context()), m_sk(core::SchnorrKeyPair::GetStrongRandomKey(m_ctx)) {}

    KeyPair(const KeyPair&) = default;
    KeyPair(KeyPair&&) noexcept = default;

    KeyPair& operator=(const KeyPair& ) = default;
    KeyPair& operator=(KeyPair&&) noexcept = default;

    const seckey& PrivKey() const
    { return m_sk; }

    [[deprecated]]
    xonly_pubkey PubKey() const
    { return SchnorrKeyPair(m_ctx, m_sk).GetPubKey(); }

    std::string GetP2TRAddress(Bech32 bech) const
    { return bech.Encode(core::SchnorrKeyPair(m_ctx, m_sk).GetPubKey(), bech32::Encoding::BECH32M); }

    std::string GetP2WPKHAddress(Bech32 bech) const
    { return bech.Encode(Hash160(EcdsaKeyPair(m_ctx, m_sk).GetPubKey()), bech32::Encoding::BECH32); }

    SchnorrKeyPair GetSchnorrKeyPair() const
    { return SchnorrKeyPair(m_ctx, m_sk); }

    EcdsaKeyPair GetEcdsaKeyPair() const
    { return EcdsaKeyPair(m_ctx, m_sk); }
};


} // utxord

