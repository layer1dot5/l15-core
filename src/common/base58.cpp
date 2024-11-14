#include "base58.hpp"

namespace l15 {

std::tuple<LegacyAddressType, bytevector> Base58::Decode(const std::string &address) const
{
    bytevector data;
    data.reserve(21);
    if (DecodeBase58Check(address, data, 21))
    {
        uint8_t prefix = data.front();
        data.erase(data.begin());
        if (prefix == 0 || prefix == 5) {
            if (chainmode != MAINNET) throw IllegalArgument("Cannot use mainnet address: " + address);

            return std::make_pair(prefix != 0 ? SCRIPT_HASH : PUB_KEY_HASH, move(data));
        }
        if (prefix == 111 || prefix == 196) {
            if (chainmode == MAINNET)  throw IllegalArgument("Cannot use non mainnet address: " + address);

            return std::make_pair(prefix == 196 ? SCRIPT_HASH : PUB_KEY_HASH, move(data));
        }
    }
    throw IllegalArgument("Invalid legacy address: " + address);
}

}
