#pragma once

#include <ranges>

#include "channel_keys.hpp"

namespace l15::core {

enum BIP86Tweak {AUTO, FORCE, SUPPRESS};

typedef cex::fixsize_vector<uint8_t, 64, secure_allocator<unsigned char>> ext_seckey;
typedef cex::fixsize_vector<uint8_t, 65> ext_pubkey;


class MasterKey
{
public:
    static const uint32_t BIP32_HARDENED_KEY_LIMIT = 0x80000000;
    static const uint32_t BIP32_BRANCH_MASK = 0x7fffffff;
    static const uint32_t BIP86_TAPROOT_ACCOUNT = 86;
private:
    const secp256k1_context* m_ctx;
    seckey mKey;
    uint256 mChainCode;

    explicit MasterKey(const secp256k1_context* ctx) : m_ctx(ctx) {}

public:
    MasterKey(const secp256k1_context* ctx, const bytevector& seed);
    explicit MasterKey(const bytevector& seed);
    MasterKey(const secp256k1_context* ctx, const ext_seckey& extkey);
    explicit MasterKey(const ext_seckey& extkey);

    MasterKey(const MasterKey&) = default;
    MasterKey(MasterKey&& ) = default;

    bool operator<(const l15::core::MasterKey& k2) const
    {
        static const std::less<seckey> keyless;
        return (mKey != k2.mKey) ? keyless(mKey, k2.mKey) : mChainCode < k2.mChainCode;
    }

    ChannelKeys MakeKey(bool do_tweak) const;
    ext_pubkey MakeExtPubKey() const;

    void DeriveSelf(uint32_t branch);

    template <std::ranges::range T>
    ChannelKeys Derive(const T& branches, BIP86Tweak bip86_tweak = AUTO) const
    {
        MasterKey branchKey(*this);

        for (const auto& b: branches) {
            branchKey.DeriveSelf(b);
        }

        bool do_tweak = (bip86_tweak == FORCE) || (bip86_tweak == AUTO && (*branches.begin() & BIP32_BRANCH_MASK) == BIP86_TAPROOT_ACCOUNT);
        return branchKey.MakeKey(do_tweak);
    }

    template <std::ranges::range T>
    void DeriveSelf(const T& branches)
    {
        for (const auto& b: branches) {
            DeriveSelf(b);
        }
    }

    ChannelKeys Derive(const std::string& path, bool for_script = false) const;

    static ext_pubkey Derive(const secp256k1_context* ctx, const ext_pubkey& extpk, uint32_t branch);
    static xonly_pubkey DerivePubKey(const secp256k1_context* ctx, const ext_pubkey& extpk, uint32_t branch);
    static xonly_pubkey GetPubKey(const secp256k1_context* ctx, const ext_pubkey& extpk);
};

} // l15::core

