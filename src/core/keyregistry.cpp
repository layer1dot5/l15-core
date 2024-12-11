
#include <execution>

#include "nlohmann/json.hpp"

#include "keyregistry.hpp"
#include "utils.hpp"
#include "base58.h"

#include "base58.hpp"

namespace l15::core {

namespace {

uint32_t derivation_index(const std::string& val)
{
    uint32_t res;
    if (val.back() == '\'') {
        std::from_chars(val.data(), val.data() + val.size() - 1, res);
        res += MasterKey::BIP32_HARDENED_KEY_LIMIT;
    }
    else {
        std::from_chars(val.data(), val.data() + val.size(), res);
    }
    return res;
}

KeyLookupFilter ParseKeyLookupFilter(const nlohmann::json& json)
{
    try {
        std::string key_type_str = json["key_type"];
        KeyLookupFilter::Type key_type = KeyLookupFilter::DEFAULT;
        if (key_type_str != "DEFAULT") {
            if (key_type_str == "TAPROOT") key_type = KeyLookupFilter::TAPROOT;
            else if (key_type_str == "TAPSCRIPT") key_type = KeyLookupFilter::TAPSCRIPT;
            else throw std::invalid_argument(std::string("key_type: ") + key_type_str);
        }

        if (!json["accounts"].is_array()) throw std::invalid_argument("accounts is missed or not an array");
        if (!json["change"].is_array()) throw std::invalid_argument("change is missed or not an array");
        if (!json["index_range"].is_string()) throw std::invalid_argument("index_range is missed or not a string");

        std::vector<uint32_t> accounts(json["accounts"].size());
        std::transform(json["accounts"].begin(), json["accounts"].end(), accounts.begin(), &derivation_index);
        std::vector<uint32_t> change(json["change"].size());
        std::transform(json["change"].begin(), json["change"].end(), change.begin(), &derivation_index);

        const std::string &index_range_str = json["index_range"];
        size_t split_pos = index_range_str.find('-');

        if (split_pos == std::string::npos) throw std::invalid_argument(std::string("index_range: ") + index_range_str);

        uint32_t index_begin = 0, index_end = 0;
        std::string_view beg_str{index_range_str.c_str(), split_pos};
        std::string end_str = index_range_str.substr(split_pos + 1);

        if (beg_str.back() == '\'') {
            if (end_str.back() != '\'') throw std::invalid_argument(std::string("index_range: ") + index_range_str + ", end bound must be hardened too");

            std::from_chars(beg_str.data(), beg_str.data() + beg_str.size() - 1, index_begin);
            index_begin += MasterKey::BIP32_HARDENED_KEY_LIMIT;
        }
        else {
            std::from_chars(beg_str.data(), beg_str.data() + beg_str.size(), index_begin);
        }

        if (end_str.back() == '\'') {
            if (beg_str.back() != '\'') throw std::invalid_argument(std::string("index_range: ") + index_range_str + ", end bound must not be hardened too");

            std::from_chars(end_str.data(), end_str.data() + end_str.size() - 1, index_end);
            index_end += MasterKey::BIP32_HARDENED_KEY_LIMIT;
        }
        else {
            std::from_chars(end_str.data(), end_str.data() + end_str.size(), index_end);
        }


        return {json["look_cache"], key_type, move(accounts), move(change), std::ranges::iota_view{index_begin, index_end}};
    }
    catch(std::exception& ex) {
        std::throw_with_nested(WrongKeyLookupFilter());
    }
}

}


KeyPair KeyRegistry::Lookup(const bytevector &keyid, const KeyLookupFilter& hint, std::function<bool(const KeyPair&, const bytevector&)> compare) const
{
    if (hint.look_cache) {
        for (const auto &sk: m_keys_cache) {
            if (KeyPair keypair(m_ctx, sk); compare(keypair, keyid)) {
                return keypair;
            }
        }
    }

    MasterKey masterCopy(mMasterKey);
    switch (hint.type) {
    case KeyLookupFilter::TAPROOT:
    case KeyLookupFilter::TAPSCRIPT:
        masterCopy.DeriveSelf(MasterKey::BIP32_HARDENED_KEY_LIMIT + MasterKey::BIP86_TAPROOT);
        break;
    case KeyLookupFilter::LEGACY:
        masterCopy.DeriveSelf(MasterKey::BIP32_HARDENED_KEY_LIMIT + MasterKey::BIP44_LEGACY);
        break;
    default:
        masterCopy.DeriveSelf(MasterKey::BIP32_HARDENED_KEY_LIMIT + MasterKey::BIP84_P2WPKH);
    }

    switch (m_chain) {
    case MAINNET:
        masterCopy.DeriveSelf(MasterKey::BIP32_HARDENED_KEY_LIMIT);
        break;
    case TESTNET:
    case REGTEST:
        masterCopy.DeriveSelf(1 + MasterKey::BIP32_HARDENED_KEY_LIMIT);
        break;
    }

    std::vector<MasterKey> accountKeys;
    accountKeys.reserve(hint.accounts.size());

    for (uint32_t acc: hint.accounts) {
        MasterKey account(masterCopy);
        account.DeriveSelf(/*MasterKey::BIP32_HARDENED_KEY_LIMIT + */acc);

        for (uint32_t ch: hint.change) {
            MasterKey change(account);
            change.DeriveSelf(ch);
            accountKeys.emplace_back(std::move(change));
        }
    }

#ifndef WASM
    std::atomic<std::shared_ptr<KeyPair>> res(nullptr);
    const uint32_t step = 64;
    uint32_t indexes[step];
    for (uint32_t key_index = *hint.index_range.begin(); key_index < *hint.index_range.end(); key_index += step) {
        std::iota(indexes, indexes + step, key_index);
        auto find_it = std::find_if(std::execution::par_unseq, indexes, indexes + step, [&](const auto &k) {
            for (const MasterKey &account: accountKeys) {
                // For TAPROOT case lets look for both tweaked and untweaked keys just to provide more robustness
                KeyPair keypair = account.Derive(std::vector<uint32_t>{k}, SUPPRESS);
                if (compare(keypair, keyid)) {
                    res = std::make_shared<KeyPair>(std::move(keypair));
                    return true;
                }
                if (hint.type == KeyLookupFilter::TAPROOT) {
                    SchnorrKeyPair kp = keypair.GetSchnorrKeyPair();
                    kp.AddTapTweak();
                    keypair = move(kp);
                    if (compare(keypair, keyid)) {
                        res = std::make_shared<KeyPair>(std::move(keypair));
                        return true;
                    }
                }
            }
            return false;
        });

        if (find_it != indexes + step) {
            std::shared_ptr<KeyPair> keypair = res.load();
            return KeyPair(move(*keypair));
        }
    }
#else
    for (uint32_t key_index: hint.index_range) {
        for (const MasterKey& account: accountKeys) {

            // For TAPROOT case lets look for both tweaked and untweaked keys just to provide more robustness

            KeyPair keypair = account.Derive(std::vector<uint32_t>{key_index}, SUPPRESS);
            if (compare(keypair, keyid))
                return keypair;

            if (hint.type == KeyLookupFilter::TAPROOT){
                SchnorrKeyPair k = keypair.GetSchnorrKeyPair();
                k.AddTapTweak();
                keypair = move(k);
                if (compare(keypair, keyid))
                     return keypair;
            }
        }
    }
#endif
    throw KeyNotFoundError();
}


KeyPair KeyRegistry::Lookup(const xonly_pubkey &pk, const KeyLookupFilter& hint) const
{
    std::cout << "lookup for pk: " << hex(pk) << std::endl;

    KeyLookupFilter taproot_hint = hint;
    if (taproot_hint.type == KeyLookupFilter::DEFAULT) {
        taproot_hint.type = KeyLookupFilter::TAPROOT;
    }
    return Lookup(pk.get_vector(), taproot_hint, [](const KeyPair& key, const bytevector& id) { return key.GetSchnorrKeyPair().GetPubKey() == id; });
}

KeyPair KeyRegistry::Lookup(const xonly_pubkey &pk, const std::string& hint_json) const
{
    try {
        auto json = nlohmann::json::parse(hint_json);
        return Lookup(pk.get_vector(), ParseKeyLookupFilter(json),
                      [](const KeyPair &key, const bytevector &id) { return key.GetSchnorrKeyPair().GetPubKey() == id; });
    }
    catch(const nlohmann::json::parse_error& e) {
        if (!m_key_type_filters.contains(hint_json)) std::throw_with_nested(IllegalArgument("key filter is unknown: " + hint_json));
        return Lookup(pk.get_vector(), m_key_type_filters.at(hint_json),
                      [](const KeyPair &key, const bytevector &id) { return key.GetSchnorrKeyPair().GetPubKey() == id; });
    }
}

KeyPair KeyRegistry::Lookup(const std::string& addr, const KeyLookupFilter& hint) const
{
    try {
        auto [witver, keyid] = Bech32(BTC, m_chain).Decode(addr);
        if (witver == 0) {
            return Lookup(keyid, hint, [&](const KeyPair &k, const bytevector &id) {
                return cryptohash<bytevector>(k.GetEcdsaKeyPair().GetPubKey(), CHash160()) == id;
            });
        }

        KeyLookupFilter taproot_hint = hint;
        if (taproot_hint.type == KeyLookupFilter::DEFAULT) {
            taproot_hint.type = KeyLookupFilter::TAPROOT;
        }
        return Lookup(keyid, taproot_hint, [](const KeyPair &k, const bytevector &id) { return k.GetSchnorrKeyPair().GetPubKey() == id; });
    }
    catch (NotBech32Encoding& e) {
        auto [type, hash] = Base58(m_chain).Decode(addr);
        if (type == PUB_KEY_HASH) {
            KeyLookupFilter p2pkh_hint = hint;
            if (p2pkh_hint.type == KeyLookupFilter::DEFAULT)
                p2pkh_hint.type = KeyLookupFilter::LEGACY;

            KeyPair keypair = Lookup(hash, p2pkh_hint, [&](const KeyPair &k, const bytevector &id) {
                return cryptohash<bytevector>(k.GetEcdsaKeyPair().GetPubKey(), CHash160()) == id;
            });
            return keypair;
        }
        if (type == SCRIPT_HASH) {
            //TODO: p2sh-p2wpkh
            throw KeyNotFoundError();
        }
        throw IllegalArgument("Wrong address: " + addr);
    }
}

KeyPair KeyRegistry::Lookup(const std::string& addr, const std::string& hint_json) const
{
    try {
        auto json = nlohmann::json::parse(hint_json);
        return Lookup(addr, ParseKeyLookupFilter(json));
    }
    catch(const nlohmann::json::parse_error& e) {
        if (!m_key_type_filters.contains(hint_json)) std::throw_with_nested(std::invalid_argument("key filter is unknown: " + hint_json));
        return Lookup(addr, m_key_type_filters.at(hint_json));
    }
}

void KeyRegistry::AddKeyType(std::string name, const string &filter_json)
{
    try {
        auto json = nlohmann::json::parse(filter_json);
        AddKeyType(move(name), ParseKeyLookupFilter(json));
    } catch (const std::exception& e) {
        std::throw_with_nested(WrongKeyLookupFilter(e.what()));
    }
}

void KeyRegistry::RemoveKeyFromCache(const string &addr)
{
    Bech32 bech(BTC, m_chain);
    uint32_t witver;
    bytevector keyid;
    std::tie(witver, keyid) = bech.Decode(addr);

    if (witver == 1)
        m_keys_cache.remove_if([&](const auto& el){ return KeyPair(m_ctx, el).GetP2TRAddress(bech) == addr; });
    else if (witver == 0)
        m_keys_cache.remove_if([&](const auto& el){ return KeyPair(m_ctx, el).GetP2WPKHAddress(bech) == addr; });
    else
        throw IllegalArgument("address: " + addr);
}

template <ChainMode M> struct XPubPrefix;
template <> struct XPubPrefix<MAINNET> { const static uint8_t value[4]; };
template <> struct XPubPrefix<TESTNET> { const static uint8_t value[4]; };
template <> struct XPubPrefix<REGTEST> { const static uint8_t value[4]; };

const uint8_t XPubPrefix<MAINNET>::value[4] {0x04, 0x88, 0xb2, 0x1e};
const uint8_t XPubPrefix<TESTNET>::value[4] {0x04, 0x35, 0x87, 0xcf};
const uint8_t XPubPrefix<REGTEST>::value[4] {0x04, 0x35, 0x87, 0xcf};


ExtPubKey::ExtPubKey(ChainMode chainmode, const std::string &extpk) : m_chainmode(chainmode)
{
    bytevector data;
    if (!DecodeBase58Check(extpk, data, 78))
        throw WrongKey("Bad base58chech encoding: " + extpk);

    const uint8_t* prefix = chainmode == ChainMode::MAINNET ? XPubPrefix<MAINNET>::value : XPubPrefix<TESTNET>::value;
    if (!std::equal(prefix, prefix+4, data.begin()))
        throw WrongKey("Wrong extpubkey prefix: " + extpk);

    if (data.size() != 78)
        throw WrongKey("Wrong extpubkey data size: " + std::to_string(data.size()));

    std::copy(data.begin() + 13, data.end(), m_extpk.begin());
}

std::string ExtPubKey::DeriveAddress(const string &path) const
{
    auto branches = spanparsing::Split(path, '/');
    std::vector<uint32_t> uint_branches;
    uint_branches.reserve(branches.size());

    for (const auto& branch: branches) {
        uint32_t index;
        if (branch[branch.size() - 1] == '\'') throw WrongDerivationPath("Can not derive pubkey using hardened algo: " + path);

            // non hardened
        auto conv_res = std::from_chars(branch.begin(), branch.end(), index);
        if (conv_res.ec == std::errc::invalid_argument) {
            throw WrongDerivationPath(path + ": " + std::string(branch.begin(), branch.end()));
        }
        uint_branches.push_back(index);
    }

    ExtPubKey extPk = *this;
    for (uint32_t b: uint_branches) {
        extPk = extPk.Derive(b);
    }

    auto tweaked_pk = SchnorrKeyPair::AddTapTweak(m_ctx, extPk.GetPubKey());

    Bech32 bech(BTC, m_chainmode);

    return bech.Encode(std::get<0>(tweaked_pk));
}

} // utxord