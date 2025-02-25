#pragma once

#include <string>

#include "transaction.h"
#include "streams.h"

#include "common.hpp"
#include "utils.hpp"

namespace l15 {

template <typename J, typename T> J JsonTx(ChainMode chain, const T& tx);

template <typename T, typename S> void LogTx(ChainMode chain, const T& tx, S& stream)
{ stream << JsonTx<nlohmann::ordered_json>(chain, tx).dump(2); }

template <typename T> void LogTx(ChainMode chain, const T& tx)
{ LogTx(chain, tx, std::clog); }

template <typename R, typename T> R LogTx(ChainMode chain, const T& tx)
{
    R res;
    cex::stream<R&> os(res);
    LogTx(chain, tx, os);
    return res;
}

CMutableTransaction DecodeHexTx(const std::string& hex);

template<typename T> std::string EncodeHexTx(const T& tx)
{
    DataStream ssTx;
    ssTx << TX_WITH_WITNESS(tx);
    return HexStr(ssTx);
}

} // l15


