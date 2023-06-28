#pragma once

#include "channel_keys.hpp"

namespace l15::core {

enum BIP86Tweak {AUTO, FORCE, SUPPRESS};

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
    MasterKey(const secp256k1_context* ctx, const std::vector<std::byte>& seed);
    explicit MasterKey(const std::vector<std::byte>& seed);

    MasterKey(const MasterKey&) = default;
    MasterKey(MasterKey&& ) = default;

    ChannelKeys MakeKey(bool do_tweak);

    void DeriveSelf(uint32_t branch);

    template <typename T>
    ChannelKeys Derive(const T& branches, BIP86Tweak bip86_tweak) const
    {
        MasterKey branchKey(*this);

        for (const auto& b: branches) {
            branchKey.DeriveSelf(b);
        }

        bool do_tweak = (bip86_tweak == FORCE) || (bip86_tweak == AUTO && (branches.front() & BIP32_BRANCH_MASK) == BIP86_TAPROOT_ACCOUNT);
        return branchKey.MakeKey(do_tweak);
    }

    ChannelKeys Derive(const std::string& path, bool for_script = false) const;
};

} // l15::core

