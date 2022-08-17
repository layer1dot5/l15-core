#pragma once

#include "common.hpp"
#include "secp256k1_frost.h"

namespace l15 {

typedef cex::fixsize_vector<uint8_t, sizeof(secp256k1_frost_secnonce::data)> frost_secnonce;
typedef cex::fixsize_vector<uint8_t, sizeof(secp256k1_frost_pubnonce::data)> frost_pubnonce;

typedef cex::fixsize_vector<uint8_t, 32> frost_sigshare;


}
