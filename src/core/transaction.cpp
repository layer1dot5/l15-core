//
// Created by lexis on 11.04.23.
//

#include "common.hpp"
#include "common_error.hpp"
#include "utils.hpp"
#include "transaction.hpp"

#undef VERSION

#include "core_io.h"

namespace l15::core {


CMutableTransaction Deserialize(const std::string &hex)
{
    CMutableTransaction tx;
    if(!DecodeHexTx(tx, hex)) {
        throw TransactionError("Error decode transaction data");
    }
    return tx;
}

//std::string Transaction::Serialize()
//{
//    return EncodeHexTx(CTransaction(m_tx));
//}

//std::string Transaction::FormatPubKeyScript(const CScript &script)
//{
//    UniValue out(UniValue::VOBJ);
//    CTxDestination address;
//    std::vector<bytevector> solns;
//    const TxoutType type{Solver(script, solns)};
//
////    if (ExtractDestination(script, address) && type != TxoutType::PUBKEY) {
////        out.pushKV("address", EncodeDestination(address));
////    }
//    out.pushKV("type", GetTxnOutputType(type));
//
//    if (type == TxoutType::WITNESS_V1_TAPROOT) {
//        out.pushKV("pubkey", hex(solns.front()));
//    }
//    if (type == TxoutType::WITNESS_V0_KEYHASH) {
//        out.pushKV("pubkeyhash", hex(solns.front()));
//    }
//
//    return out.write(2);
//}

bool IsTaproot(const CTxOut &out)
{
    int witversion;
    std::vector<unsigned char> witnessprogram;
    bool segwit =  out.scriptPubKey.IsWitnessProgram(witversion, witnessprogram);
    return segwit && witversion == 1;
}

std::string GetTaprootPubKey(const CTxOut &out)
{
    int witversion;
    bytevector witnessprogram;
    if (!out.scriptPubKey.IsWitnessProgram(witversion, witnessprogram)) {
        throw TransactionError("Not SegWit output");
    }
    if (witversion != 1) {
        throw TransactionError("Wrong SegWit version: " + std::to_string(witversion));
    }
    return hex(witnessprogram);
}

std::string GetTaprootAddress(const std::string& chain_mode, const std::string& pubkey)
{
    if (chain_mode == "testnet") {
        Bech32Coder<IBech32Coder::BTC, IBech32Coder::TESTNET> bech32;
        return bech32.Encode(unhex<xonly_pubkey>(pubkey));
    }
    else if (chain_mode == "mainnet") {
        Bech32Coder<IBech32Coder::BTC, IBech32Coder::MAINNET> bech32;
        return bech32.Encode(unhex<xonly_pubkey>(pubkey));
    }
    else if (chain_mode == "regtest") {
        Bech32Coder<IBech32Coder::BTC, IBech32Coder::REGTEST> bech32;
        return bech32.Encode(unhex<xonly_pubkey>(pubkey));
    }
    else {
        throw IllegalArgumentError(std::string(chain_mode));
    }
}

} // core
