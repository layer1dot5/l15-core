#pragma once

#include "base58.hpp"
#include "bech32.hpp"
#include "keypair_common.hpp"
#include "schnorr.hpp"
#include "ecdsa.hpp"

namespace l15::core {

class KeyPair : public KeyPairBase
{
    const secp256k1_context* m_ctx;
    seckey m_sk;
public:

    KeyPair(const secp256k1_context* ctx) : m_ctx(ctx), m_sk(GetStrongRandomKey(m_ctx)) {}
    KeyPair(const secp256k1_context* ctx, seckey sk) : m_ctx(ctx), m_sk(move(sk)) {}
    explicit KeyPair(seckey sk) : KeyPair(GetStaticSecp256k1Context(), move(sk)) {}
    KeyPair() : m_ctx(GetStaticSecp256k1Context()), m_sk(GetStrongRandomKey(m_ctx)) {}

    explicit KeyPair(SchnorrKeyPair&& keypair) : m_ctx(keypair.Secp256k1Context()), m_sk(move(keypair.m_local_sk)) {}
    explicit KeyPair(EcdsaKeyPair&& keypair) : m_ctx(keypair.Secp256k1Context()), m_sk(move(keypair.m_sk)) {}

    KeyPair(const KeyPair&) = default;
    KeyPair(KeyPair&&) noexcept = default;

    KeyPair& operator=(const KeyPair& ) = default;
    KeyPair& operator=(KeyPair&&) noexcept = default;
    KeyPair& operator=(const SchnorrKeyPair& k)
    {
        m_ctx = k.Secp256k1Context();
        m_sk = k.GetPrivKey();
        return *this;
    }
    KeyPair& operator=(SchnorrKeyPair&& k) noexcept
    {
        m_ctx = k.Secp256k1Context();
        m_sk = move(k.m_local_sk);
        return *this;
    }
    KeyPair& operator=(const EcdsaKeyPair& k)
    {
        m_ctx = k.Secp256k1Context();
        m_sk = k.GetPrivKey();
        return *this;
    }
    KeyPair& operator=(EcdsaKeyPair&& k) noexcept
    {
        m_ctx = k.Secp256k1Context();
        m_sk = move(k.m_sk);
        return *this;
    }

    const secp256k1_context* Secp256k1Context() const noexcept
    { return m_ctx; }

    const seckey& PrivKey() const
    { return m_sk; }

    [[deprecated]]
    xonly_pubkey PubKey() const
    { return SchnorrKeyPair(m_ctx, m_sk).GetPubKey(); }

    std::string GetP2TRAddress(Bech32 bech) const
    { return bech.Encode(GetSchnorrKeyPair().GetPubKey(), bech32::Encoding::BECH32M); }

    std::string GetP2WPKHAddress(Bech32 bech) const
    { return bech.Encode(cryptohash<bytevector>(GetEcdsaKeyPair().GetPubKey(), CHash160()), bech32::Encoding::BECH32); }

    std::string GetP2PKHAddress(ChainMode chain) const
    { return Base58(chain).Encode(cryptohash<bytevector>(GetEcdsaKeyPair().GetPubKey(), CHash160()), PUB_KEY_HASH); }

    std::string GetP2WPKH_P2SHAddress(ChainMode chain) const
    {
        CScript redeemScript;
        redeemScript << 0 << cryptohash<bytevector>(GetEcdsaKeyPair().GetPubKey(), CHash160());
        return Base58(chain).Encode(cryptohash<bytevector>(redeemScript, CHash160()), SCRIPT_HASH);
    }

    SchnorrKeyPair GetSchnorrKeyPair() const
    { return SchnorrKeyPair(m_ctx, m_sk); }

    EcdsaKeyPair GetEcdsaKeyPair() const
    { return EcdsaKeyPair(m_ctx, m_sk); }
};


} // utxord

