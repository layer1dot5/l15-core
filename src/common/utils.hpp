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

CAmount GetOutputAmount(const std::string& txoutstr);
uint32_t GetCsvInBlocks(uint32_t blocks);

template <typename T> void LogTx(const T& tx);

enum ChainType {BTC, L15};
enum ChainMode {MAINNET, TESTNET, REGTEST};

}
