#pragma once

#include <string>
#include <vector>

#include "smartinserter.hpp"

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

CAmount GetOutputAmount(const std::string& txoutstr);
uint32_t GetCsvInBlocks(uint32_t blocks);

template <typename T> void LogTx(const T& tx);

enum ChainType {BTC, L15};
enum ChainMode {MAINNET, TESTNET, REGTEST};

template<typename Stream>
void WriteCompactSize(Stream& os, uint64_t nSize)
{
    if (nSize < 253)
    {
        ser_writedata8(os, nSize);
    }
    else if (nSize <= std::numeric_limits<uint16_t>::max())
    {
        ser_writedata8(os, 253);
        ser_writedata16(os, nSize);
    }
    else if (nSize <= std::numeric_limits<unsigned int>::max())
    {
        ser_writedata8(os, 254);
        ser_writedata32(os, nSize);
    }
    else
    {
        ser_writedata8(os, 255);
        ser_writedata64(os, nSize);
    }
    return;
}

/**
 * Decode a CompactSize-encoded variable-length integer.
 *
 * As these are primarily used to encode the size of vector-like serializations, by default a range
 * check is performed. When used as a generic number encoding, range_check should be set to false.
 */
template<typename Stream>
uint64_t ReadCompactSize(Stream& is, bool range_check = true)
{
    uint8_t chSize = ser_readdata8(is);
    uint64_t nSizeRet = 0;
    if (chSize < 253)
    {
        nSizeRet = chSize;
    }
    else if (chSize == 253)
    {
        nSizeRet = ser_readdata16(is);
        if (nSizeRet < 253)
            throw FormatError("non-canonical ReadCompactSize()");
    }
    else if (chSize == 254)
    {
        nSizeRet = ser_readdata32(is);
        if (nSizeRet < 0x10000u)
            throw FormatError("non-canonical ReadCompactSize()");
    }
    else
    {
        nSizeRet = ser_readdata64(is);
        if (nSizeRet < 0x100000000ULL)
            throw FormatError("non-canonical ReadCompactSize()");
    }
    if (range_check && nSizeRet > MAX_SIZE) {
        throw FormatError("ReadCompactSize(): size too large");
    }
    return nSizeRet;
}


}
