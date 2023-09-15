#pragma once

#include <list>
#include <unordered_set>
#include <set>
#include <concepts>

#include "common.hpp"
#include "channel_keys.hpp"
#include "master_key.hpp"

namespace l15::core {

struct PubKeyTypeTraits {
    typedef xonly_pubkey key_type;
    typedef ext_pubkey extkey_type;
};

struct KeyTypeTraits {
    typedef seckey key_type;
    typedef ext_seckey extkey_type;
};

//class IPubKeyFactory
//{
//public:
//    virtual xonly_pubkey MakePubKey(uint32_t index) = 0;
//    virtual std::optional<uint32_t> LookUpPubKey(const xonly_pubkey& pk, uint32_t max_limit) = 0;
//    virtual ~IPubKeyFactory() = default;
//};
//
//
//class IKeyFactory /*: public IPubKeyFactory*/
//{
//public:
//    virtual ChannelKeys MakeKey(uint32_t index) = 0;
//    virtual std::optional<ChannelKeys> LookUpKey(const xonly_pubkey& pk, uint32_t max_limit) = 0;
//    virtual ~IKeyFactory() = default;
//};


//class SinglePubKey : public IPubKeyFactory
//{
//    xonly_pubkey m_pk;
//public:
//    explicit SinglePubKey(xonly_pubkey pk) : m_pk(move(pk)) {}
//    SinglePubKey(SinglePubKey&& v) noexcept = default;
//    ~SinglePubKey() override = default;
//
//    xonly_pubkey MakePubKey(uint32_t index) override
//    { return m_pk; }
//    std::optional<uint32_t> LookUpPubKey(const xonly_pubkey& pk, uint32_t ) override
//    { if (pk == m_pk) return 0; else return {}; }
//};
//
//class SingleKey : public IKeyFactory
//{
//    ChannelKeys m_keypair;
//public:
//    explicit SingleKey(ChannelKeys keypair) : m_keypair(move(keypair)) {}
//    SingleKey(secp256k1_context* ctx, seckey key) : m_keypair(ctx, move(key)) {}
//    SingleKey(SingleKey&& ) noexcept = default;
//    ~SingleKey() override = default;
//
//    ChannelKeys MakeKey(uint32_t index) override
//    { return m_keypair; }
//    std::optional<ChannelKeys> LookUpKey(const xonly_pubkey& pk, uint32_t max_limit) override
//    { if (pk == m_keypair.GetLocalPubKey()) return m_keypair; else return {}; }
//
//};

class PubKeyFactory
{
    secp256k1_context* m_ctx;
    ext_pubkey m_extpk;
public:
    PubKeyFactory(secp256k1_context* ctx, ext_pubkey extpk) : m_ctx(ctx), m_extpk(move(extpk)) {}
    PubKeyFactory(ext_pubkey extpk) : PubKeyFactory(ChannelKeys::GetStaticSecp256k1Context(), extpk) {}
    PubKeyFactory(PubKeyFactory&& v) noexcept = default;
    ~PubKeyFactory() = default;

    xonly_pubkey MakeKey(uint32_t index);
};

class KeyFactory
{
    MasterKey mMasterKey;
    bool m_bip86tweak;
public:
    KeyFactory(MasterKey&& key, bool bip86tweak)
        : mMasterKey(move(key)), m_bip86tweak(bip86tweak) {}
    KeyFactory(KeyFactory&& v) noexcept = default;
    ~KeyFactory() = default;

    ChannelKeys MakeKey(uint32_t index);
};

class PubKeyRegistry
{
    secp256k1_context* m_ctx;
    std::unordered_set<xonly_pubkey> m_single_keys;
    std::set<ext_pubkey> m_extkeys;

public:
    explicit PubKeyRegistry(secp256k1_context* ctx) : m_ctx(ctx) {}
    PubKeyRegistry() : PubKeyRegistry(ChannelKeys::GetStaticSecp256k1Context()) {}

    void AddSingleKey(xonly_pubkey key)
    { m_single_keys.emplace(move(key)); }

    void AddKeyFactory(ext_pubkey extkey)
    { m_extkeys.emplace(move(extkey)); }

    bool LookUpPubKey(const xonly_pubkey& pk, uint32_t index_limit) const;
};

class KeyRegistry
{
    secp256k1_context* m_ctx;
    bool m_bip86;
    std::unordered_map<xonly_pubkey, ChannelKeys> m_single_keys;
    std::set<MasterKey> m_extkeys;
public:
    KeyRegistry(secp256k1_context* ctx, bool bip86tweak) : m_ctx(ctx), m_bip86(bip86tweak) {}
    explicit KeyRegistry(bool bip86tweak) : KeyRegistry(ChannelKeys::GetStaticSecp256k1Context(), bip86tweak) {}

    void AddSingleKey(ChannelKeys&& keypair)
    { m_single_keys.emplace(xonly_pubkey(keypair.GetLocalPubKey()), move(keypair)); }

    void AddKeyFactory(MasterKey&& extkey)
    { m_extkeys.emplace(move(extkey)); }

    std::optional<ChannelKeys> LookUpPubKey(const xonly_pubkey& pk, uint32_t index_limit) const;
};

} // l15::core

