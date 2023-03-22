#include "common.hpp"

#include "script/script.h"

namespace l15 {

CScript &operator<<(CScript &script, const xonly_pubkey &pk)
{ return script << pk.get_vector(); }

namespace {

constexpr std::array<std::array<char, 2>, 256> CreateByteToHexMap()
{
    constexpr char hexmap[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    std::array<std::array<char, 2>, 256> byte_to_hex{};
    for (size_t i = 0; i < byte_to_hex.size(); ++i) {
        byte_to_hex[i][0] = hexmap[i >> 4];
        byte_to_hex[i][1] = hexmap[i & 15];
    }
    return byte_to_hex;
}

}

const std::array<std::array<char, 2>, 256> byte_to_hex = CreateByteToHexMap();
std::array<uint8_t, 16> hex_to_val = {};

}
