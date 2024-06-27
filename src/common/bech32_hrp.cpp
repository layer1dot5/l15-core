#include "bech32.hpp"

namespace l15 {

const char* const Hrp<BTC, MAINNET>::value = "bc";
const char* const Hrp<BTC, TESTNET>::value = "tb";
const char* const Hrp<BTC, REGTEST>::value = "bcrt";
const char* const Hrp<L15, MAINNET>::value = "l15";
const char* const Hrp<L15, TESTNET>::value = "l15t";
const char* const Hrp<L15, REGTEST>::value = "l15rt";

}