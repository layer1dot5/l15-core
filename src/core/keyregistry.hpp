#pragma once

#include <functional>
#include <list>
#include <ranges>
#include <unordered_map>

#include "utils.hpp"
#include "schnorr.hpp"
#include "ecdsa.hpp"
#include "keypair.hpp"
#include "master_key.hpp"

namespace l15::core {

class WrongKeyLookupFilter : public Error
{
public:
    WrongKeyLookupFilter() = default;
    explicit WrongKeyLookupFilter(std::string&& details) : Error(move(details)) {}
    ~WrongKeyLookupFilter() override = default;

    const char* what() const noexcept override
    { return "WrongKeyLookupFilter"; }
};

class KeyNotFoundError : public Error
{
public:
    KeyNotFoundError() = default;
    explicit KeyNotFoundError(std::string&& details) : Error(move(details)) {}
    ~KeyNotFoundError() override = default;

    const char* what() const noexcept override
    { return "KeyNotFoundError"; }
};

struct KeyLookupFilter
{
    enum Type {DEFAULT, TAPROOT, TAPSCRIPT, LEGACY};

    bool look_cache;
    Type type;
    std::vector<uint32_t> accounts;
    std::vector<uint32_t> change;
    std::ranges::iota_view<uint32_t, uint32_t> index_range;
};

class KeyRegistry
{
    const secp256k1_context* m_ctx;
    ChainMode m_chain;

    std::unordered_map<std::string, KeyLookupFilter> m_key_type_filters;

    MasterKey mMasterKey;
    std::list<seckey> m_keys_cache;

public:
    KeyRegistry(const secp256k1_context* ctx, ChainMode chain, const sensitive_bytevector& seed): m_ctx(ctx), m_chain(chain), m_key_type_filters(10), mMasterKey(m_ctx, seed) {}
    KeyRegistry(ChainMode chain, const std::string& seedhex): KeyRegistry(KeyPair::GetStaticSecp256k1Context(), chain, unhex<sensitive_bytevector>(seedhex)) {}

    const secp256k1_context* Secp256k1Context() const
    { return m_ctx; }

    void AddKeyType(std::string name, KeyLookupFilter filter)
    { m_key_type_filters.emplace(move(name), std::move(filter)); }
    void AddKeyType(std::string name, const std::string& filter_json);
    void RemoveKeyType(const std::string& name)
    { m_key_type_filters.erase(name); }

    void AddKeyToCache(seckey sk)
    { m_keys_cache.emplace_back(move(sk)); }

    void AddKeyToCache(const KeyPair& key)
    { m_keys_cache.emplace_back(key.PrivKey()); }

    void AddKeyToCache(const std::string& key)
    { m_keys_cache.emplace_back(unhex<seckey>(key)); }

    void RemoveKeyFromCache(const std::string& addr);

    void RemoveKeyFromCache(seckey sk)
    { m_keys_cache.remove_if([&](const auto& el){ return el == sk; }); }

    KeyPair Derive(const std::string& path, bool for_script) const
    { return KeyPair(mMasterKey.Derive(path, for_script)); }

    KeyPair Lookup(const bytevector& keyid, const KeyLookupFilter& hint, std::function<bool(const KeyPair&, const bytevector&)>) const;
    KeyPair Lookup(const xonly_pubkey& pk, const KeyLookupFilter& hint) const;
    KeyPair Lookup(const xonly_pubkey& pk, const std::string& hint_json) const;
    KeyPair Lookup(const std::string& addr, const KeyLookupFilter& hint) const;
    KeyPair Lookup(const std::string& addr, const std::string& hint_json) const;
};

class ExtPubKey
{
    ChainMode m_chainmode;
    const secp256k1_context* m_ctx;
    ext_pubkey m_extpk;

public:
    ExtPubKey(ChainMode chainmode, const secp256k1_context* ctx, ext_pubkey extpk): m_chainmode(chainmode), m_ctx(ctx), m_extpk(move(extpk)) {}
    ExtPubKey(ChainMode chainmode, const std::string& extpk);

    ExtPubKey(const ExtPubKey&) = default;
    ExtPubKey& operator=(const ExtPubKey&) = default;
    ExtPubKey& operator=(ExtPubKey&&) noexcept = default;

    uint256 GetChainCode() const
    { return uint256(Span<const uint8_t >(m_extpk.data(), 32)); }
    xonly_pubkey GetPubKey() const
    { return xonly_pubkey(m_extpk.begin() + 33, m_extpk.end()); }

    ExtPubKey Derive(uint32_t index) const
    { return ExtPubKey(m_chainmode, m_ctx, MasterKey::Derive(m_ctx, m_extpk, index)); }

    std::string DeriveAddress(const std::string& path) const;
};


} // l15::core

