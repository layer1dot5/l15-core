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
        return Bech32Coder(BTC, TESTNET).Encode(unhex<xonly_pubkey>(pubkey));
    }
    else if (chain_mode == "mainnet") {
        return Bech32Coder(BTC, MAINNET).Encode(unhex<xonly_pubkey>(pubkey));
    }
    else if (chain_mode == "regtest") {
        return Bech32Coder(BTC, REGTEST).Encode(unhex<xonly_pubkey>(pubkey));
    }
    else {
        throw IllegalArgumentError(std::string(chain_mode));
    }
}

std::string GetAddress(const std::string& chain_mode, const bytevector& pubkeyscript)
{
    int witver;
    bytevector witnessprogram;
    CScript script(pubkeyscript.begin(), pubkeyscript.end());
    bool segwit =  script.IsWitnessProgram(witver, witnessprogram);
    if (segwit) {
        if (chain_mode == "testnet") {
            return Bech32Coder(BTC, TESTNET).Encode(witnessprogram, witver == 0 ? bech32::Encoding::BECH32 : bech32::Encoding::BECH32M);
        }
        else if (chain_mode == "mainnet") {
            return Bech32Coder(BTC, MAINNET).Encode(witnessprogram, witver == 0 ? bech32::Encoding::BECH32 : bech32::Encoding::BECH32M);
        }
        else if (chain_mode == "regtest") {
            return Bech32Coder(BTC, REGTEST).Encode(witnessprogram, witver == 0 ? bech32::Encoding::BECH32 : bech32::Encoding::BECH32M);
        }
        else {
            throw IllegalArgumentError(std::string(chain_mode));
        }
    }
    else {
        return "";
        //throw TransactionError("Not SegWit");
    }
}

} // core
