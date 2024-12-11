#pragma once

#include "script/script.h"
#include "base58.h"

#include "utils.hpp"

#include "smartinserter.hpp"

namespace l15 {

enum LegacyAddressType {PUB_KEY_HASH, SCRIPT_HASH};

class Base58
{
    ChainMode chainmode;
public:
    Base58() : chainmode(MAINNET) {}
    Base58(ChainMode m) : chainmode(m) {}

    Base58(const Base58&) = default;
    Base58& operator= (const Base58&) = default;

    ChainMode GetChainMode() const
    { return chainmode; }

    template <typename KeyType>
    std::string Encode(const KeyType& data, LegacyAddressType type) const
    {
        bytevector buf;
        buf.reserve(data.size() + 1);
        if (chainmode == MAINNET)
            buf.push_back(type==PUB_KEY_HASH ? (uint8_t)0 : (uint8_t)5);
        else // Any chain has same prefix same except main
            buf.push_back(type==PUB_KEY_HASH ? (uint8_t)111 : (uint8_t)196);

        std::copy(data.begin(), data.end(), cex::smartinserter(buf, buf.end()));

        return EncodeBase58Check(buf);
    }

    std::tuple<LegacyAddressType, bytevector> Decode(const std::string& address) const;
};

}
