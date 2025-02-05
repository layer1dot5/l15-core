#pragma once

#include <string>
#include <vector>

#include "nlohmann/json.hpp"
#include "wrapstream.hpp"

#include "util/strencodings.h"
#include "amount.h"

#include "common.hpp"
#include "feerate.h"
#include "consensus.h"
#include "policy.h"

namespace l15 {

CAmount ParseAmount(const std::string& amountstr);
std::string FormatAmount(CAmount amount);
CAmount CalculateOutputAmount(CAmount input_amount, CAmount fee_rate, const CMutableTransaction&);
template<typename T> CAmount CalculateTxFee(CAmount fee_rate, const T& tx);
constexpr CAmount Dust(const CAmount fee_rate = DUST_RELAY_TX_FEE) {return CFeeRate(fee_rate).GetFee(43 + 32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4);}

bytevector ScriptHash(const CScript &script);
bytevector CreatePreimage();

template <typename R, typename D, typename H>
constexpr R cryptohash(const D& data, H h = {})
{
    R out(H::OUTPUT_SIZE);
    h.Write(data.data(), data.size()).Finalize(out.data());
    return out;
}

template <typename R, typename DATA>
constexpr R cryptohash(const DATA& preimage, CHash160 h)
{
    R out(CHash160::OUTPUT_SIZE);
    h.Write(preimage).Finalize(out);
    return out;
}

template <typename R, typename DATA>
constexpr R cryptohash(const DATA& preimage, CHash256 h)
{
    R out(CHash256::OUTPUT_SIZE);
    h.Write(preimage).Finalize(out);
    return out;
}

uint32_t GetCsvInBlocks(uint32_t blocks);

enum ChainType {BTC, L15};
enum ChainMode {MAINNET, TESTNET, REGTEST};

// template<typename S>
// void WriteCompactSize(S& os, uint64_t v)
// {
//     static_assert(sizeof(typename S::value_type) == 1);
//
//     if (v < 253)
//         os << static_cast<uint8_t>(v);
//     else if (v <= std::numeric_limits<uint16_t>::max())
//         os << 253 << static_cast<uint16_t>(v);
//     else if (v <= std::numeric_limits<uint32_t>::max())
//         os << 254 << static_cast<uint32_t>(v);
//     else
//         os << 255 << v;
// }

/**
 * Decode a CompactSize-encoded variable-length integer.
 *
 * As these are primarily used to encode the size of vector-like serializations, by default a range
 * check is performed. When used as a generic number encoding, range_check should be set to false.
 */
// template<typename S>
// uint64_t ReadCompactSize(S& is, bool range_check = true)
// {
//     static_assert(sizeof(typename S::value_type) == 1);
//
//     uint64_t ret = 0;
//     uint8_t first;
//     is >> first;
//
//     if (first < 253)
//         ret = first;
//     else if (first == 253) {
//         uint16_t v; is >> v;
//         if (v < 253)
//             throw FormatError("non-canonical ReadCompactSize()");
//         ret = v;
//     }
//     else if (first == 254) {
//         uint32_t v; is >> v;
//         if (v < 0x10000u)
//             throw FormatError("non-canonical ReadCompactSize()");
//         ret = v;
//     }
//     else {
//         uint64_t v; is >> v;
//         if (v < 0x100000000ULL)
//             throw FormatError("non-canonical ReadCompactSize()");
//         ret = v;
//     }
//     if (range_check && ret > MAX_SIZE) {
//         throw FormatError("ReadCompactSize(): size too large");
//     }
//     return ret;
// }

}
