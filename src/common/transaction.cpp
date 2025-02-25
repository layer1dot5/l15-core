
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
        jin["scriptSig"] = in.scriptSig;

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
