#pragma once

#include <string>
#include <unordered_map>

#include "transaction.h"

namespace l15::core {

CMutableTransaction Deserialize(const std::string& hex);
bool IsTaproot(const CTxOut& out);
std::string GetTaprootPubKey(const CTxOut& out);



//class Transaction
//{
//
//    static bool IsTaproot(const CTxOut& out);
//    static std::string GetTaprootPubKey(const CTxOut& out);
//public:
//    CMutableTransaction m_tx;
//    void Deserialize(const std::string& hex);
//    std::string Serialize();
////
////    std::
//
//
//};

} // l15::core


