#pragma once

#include <string>
#include <unordered_map>

#include "transaction.h"

namespace l15::core {

CMutableTransaction Deserialize(const std::string& hex);
bool IsTaproot(const CTxOut& out);
std::string GetTaprootPubKey(const CTxOut& out);
std::string GetTaprootAddress(const std::string& chain_mode, const std::string& pubkey);

std::string GetAddress(const std::string& chain_mode, const bytevector& pubkeyscript);


} // l15::core


