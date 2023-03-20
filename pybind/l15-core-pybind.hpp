#pragma once

#include <curses.h>
#include "channel_keys.hpp"
#include "../src/core/channel_keys.hpp"
#include "../contrib/cex/fixsizevector.hpp"

class ChannelKeysImpl : public l15::core::ChannelKeys {
    static struct secp256k1_context_struct *ctx;

public:
    static struct secp256k1_context_struct * GetSecp256k1Context();

    ChannelKeysImpl(cex::fixsize_vector<uint8_t, 32> sk) : l15::core::ChannelKeys(GetSecp256k1Context(), move(sk)) {}

    using ChannelKeys::GetLocalPrivKey;
    using ChannelKeys::GetLocalPubKey;
};

