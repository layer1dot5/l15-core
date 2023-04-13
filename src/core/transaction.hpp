#pragma once

#include <string>
#include <unordered_map>

#include "transaction.h"

namespace l15::core {

CMutableTransaction Deserialize(const std::string& hex);
bool IsTaproot(const CTxOut& out);
std::string GetTaprootPubKey(const CTxOut& out);
std::string GetTaprootAddress(const std::string& chain_mode, const std::string& pubkey);

bool VerifySchnorr(const std::string& pk, const std::string& sig, const std::string msg);




} // l15::core


