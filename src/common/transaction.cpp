//
// Created by lexis on 11.04.23.
//

#include "common.hpp"
#include "common_error.hpp"
#include "bech32.hpp"
#include "transaction.hpp"

#undef VERSION

#include "core_io.h"

namespace l15 {

CMutableTransaction DecodeHexTx(const std::string &hex)
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
        return Bech32(BTC, TESTNET).Encode(unhex<xonly_pubkey>(pubkey));
    }
    else if (chain_mode == "mainnet") {
        return Bech32(BTC, MAINNET).Encode(unhex<xonly_pubkey>(pubkey));
    }
    else if (chain_mode == "regtest") {
        return Bech32(BTC, REGTEST).Encode(unhex<xonly_pubkey>(pubkey));
    }

    throw IllegalArgument(std::string("chain_mode: ") + chain_mode);
}

std::string GetAddress(const std::string& chain_mode, const bytevector& pubkeyscript)
{
    int witver;
    bytevector witnessprogram;
    CScript script(pubkeyscript.begin(), pubkeyscript.end());
    bool segwit =  script.IsWitnessProgram(witver, witnessprogram);
    if (segwit) {
        if (chain_mode == "testnet") {
            return Bech32(BTC, TESTNET).Encode(witnessprogram, witver == 0 ? bech32::Encoding::BECH32 : bech32::Encoding::BECH32M);
        }
        else if (chain_mode == "mainnet") {
            return Bech32(BTC, MAINNET).Encode(witnessprogram, witver == 0 ? bech32::Encoding::BECH32 : bech32::Encoding::BECH32M);
        }
        else if (chain_mode == "regtest") {
            return Bech32(BTC, REGTEST).Encode(witnessprogram, witver == 0 ? bech32::Encoding::BECH32 : bech32::Encoding::BECH32M);
        }

        throw IllegalArgument(std::string("chain_mode: " + chain_mode));
    }
    else {
        return "";
    }
}

template <typename J, typename T> J JsonTx(ChainMode chain, const T& tx)
{
    J res;
    res["txid"] = tx.GetHash().GetHex();
    res["version"] = tx.nVersion;
    res["nLockTime"] = tx.nLockTime;
    for(const auto& in: tx.vin)
    {
        nlohmann::ordered_json jin;
        jin["txid"] = in.prevout.hash.GetHex();
        jin["n"] = in.prevout.n;
        jin["nSequence"] = in.nSequence;

        for(const auto& wel: in.scriptWitness.stack)
            jin["witness"].emplace_back(HexStr(wel));

        res["vin"].emplace_back(move(jin));
    }
    for(const auto& out: tx.vout)
    {
        nlohmann::ordered_json jout;
        jout["amount"] = out.nValue;

        bytevector wp;
        int wver;
        if(out.scriptPubKey.IsWitnessProgram(wver, wp))
        {
            if(wver == 0) jout["address"] = Bech32(BTC, chain).Encode(wp, bech32::Encoding::BECH32);
            else if (wver == 1) jout["address"] = Bech32(BTC, chain).Encode(wp, bech32::Encoding::BECH32M);
        }
        jout["scriptPubKey"] = hex(out.scriptPubKey);

        res["vout"].emplace_back(move(jout));
    }
    return res;
}

template nlohmann::json JsonTx<nlohmann::json, CMutableTransaction>(ChainMode chain, const CMutableTransaction& tx);
template nlohmann::json JsonTx<nlohmann::json, CTransaction>(ChainMode chain, const CTransaction& tx);
template nlohmann::ordered_json JsonTx<nlohmann::ordered_json, CMutableTransaction>(ChainMode chain, const CMutableTransaction& tx);
template nlohmann::ordered_json JsonTx<nlohmann::ordered_json, CTransaction>(ChainMode chain, const CTransaction& tx);

} // core
