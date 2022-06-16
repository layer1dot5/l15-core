#pragma once

#include "common.hpp"
#include "secp256k1_frost.h"

namespace l15 {

typedef std::array<uint8_t, sizeof(secp256k1_frost_secnonce::data)> frost_secnonce;
typedef std::array<uint8_t, sizeof(secp256k1_frost_pubnonce::data)> frost_pubnonce;

}
