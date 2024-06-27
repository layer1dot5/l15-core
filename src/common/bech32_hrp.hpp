#pragma once

#include "utils.hpp"

namespace l15 {

template <ChainType C, ChainMode M> struct Hrp;
template <> struct Hrp<BTC, MAINNET> { const static char* const value; };
template <> struct Hrp<BTC, TESTNET> { const static char* const value; };
template <> struct Hrp<BTC, REGTEST> { const static char* const value; };
template <> struct Hrp<L15, MAINNET> { const static char* const value; };
template <> struct Hrp<L15, TESTNET> { const static char* const value; };
template <> struct Hrp<L15, REGTEST> { const static char* const value; };

}