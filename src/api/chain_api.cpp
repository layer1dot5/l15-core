#include "chain_api.hpp"
#include "wallet_api.hpp"
#include "transaction.hpp"

#include "script/script.h"
#include "script/interpreter.h"
#include "util/strencodings.h"
#include "crypto/sha256.h"
#include "primitives/transaction.h"
#include "uint256.h"
#include "univalue.h"
#include "amount.h"
#include "core_io.h"

#include <string>
#include <iostream>
#include <algorithm>
#include <chrono>
#include <thread>


namespace l15::core {


namespace {

    const char* const GETBLOCKCOUNT = "getblockcount";
    const char* const SENDTOADDRESS = "sendtoaddress";
    const char* const GETTXOUT = "gettxout";
    const char* const SENDRAWTRANSACTION = "sendrawtransaction";
    const char* const GETRAWTRANSACTION = "getrawtransaction";
    const char* const TESTMEMPOOLACCEPT = "testmempoolaccept";
    const char* const GETNEWADDRESS = "getnewaddress";
    const char* const GENERATETOADDRESS = "generatetoaddress";
    const char* const STOP = "stop";
    const char* const CREATEWALLET = "createwallet";
    const char* const GETWALLETINFO = "getwalletinfo";
    const char* const WALLETPASSPHRASE = "walletpassphrase";
    const char* const GETBLOCK = "getblock";
    const char* const GETZMQNOTIFICATIONS = "getzmqnotifications";
    const char* const ESTIMATESMARTFEE = "estimatesmartfee";

}

std::regex ChainApi::sNewlineRegExp("\n+");


uint32_t ChainApi::GetChainHeight() const
{
    return std::stoul(Call(GETBLOCKCOUNT));
}

std::string ChainApi::SendToAddress(std::string address, std::string amount) const
{
    return std::regex_replace(Call(SENDTOADDRESS, move(address), move(amount)), sNewlineRegExp, "");
}

std::string ChainApi::GetTxOut(std::string txidhex, std::string out) const
{
    return Call(GETTXOUT, move(txidhex), move(out));
}

//transaction_ptr ChainApi::CreateSegwitTx(const CScript &script, const ChainApi::string_pair_t &utxo, const std::vector<string_pair_t>& outs_addr_amount, uint32_t locktime) const
//{
//    std::unique_ptr<CMutableTransaction> tx(new CMutableTransaction());
//    tx->nLockTime = locktime;
//
//    // Fill outputs
//    for(const string_pair_t& addr_amount: outs_addr_amount)
//    {
//        auto addr_id = Bech32Decode(addr_amount.first);
//
//        if(addr_id.size() == 20)
//        {
//            std::clog << "Spend to P2WPKH address: " << addr_amount.first << std::endl;
//        }
//        else if(addr_id.size() == 32)
//        {
//            std::clog << "Spend to P2WSH address: " << addr_amount.first << std::endl;
//        }
//        else
//        {
//            throw std::runtime_error(std::string("Wrong Bech32 address: ") + addr_amount.first);
//        }
//
//        CScript outpubkeyscript;
//        outpubkeyscript << 0;
//        outpubkeyscript << addr_id;
//
//        CAmount outAmount;
//        if(!ParseFixedPoint(addr_amount.second, 8, &outAmount))
//        {
//            throw std::runtime_error(std::string("Error parsing out amount: ") + addr_amount.second);
//        }
//        tx->vout.emplace_back(CTxOut(outAmount, outpubkeyscript));
//    }
//
//    // Fill single input
//    std::string txoutstr = GetTxOut(utxo.first, utxo.second);
//
//    CAmount amount;
//    UniValue txout;
//    txout.read(txoutstr);
//
//    const std::string &amountstr = find_value(txout, "value").getValStr();
//    if(!ParseFixedPoint(amountstr, 8, &amount))
//    {
//        throw std::runtime_error(std::string("Error parsing prevout amount: ") + amountstr);
//    }
//
//    std::clog << "Tx input amount: " << amountstr << std::endl;
//
//    char *endp;
//    uint32_t prevoutnum = std::strtoul(utxo.second.c_str(), &endp, 10);
//
//    std::vector<uint8_t> scripthash;
//    scripthash.resize(CSHA256::OUTPUT_SIZE);
//    //memset(scripthash, 0, CSHA256::OUTPUT_SIZE);
//    CSHA256().Write(script.data(), script.size()).Finalize(scripthash.data());
//
//    std::string scripthashhex = HexStr(Span<const unsigned char>(scripthash.data(), CSHA256::OUTPUT_SIZE));
//    std::clog << "Script hash:\t" << scripthashhex << std::endl;
//
//    std::string from_address = m_wallet.Bech32Encode(scripthash.begin(), scripthash.end());
//
//    std::clog << "Spend from P2WSH address:\t" << from_address << std::endl;
//
//
//    CTxIn input(uint256S(utxo.first), prevoutnum, CScript(), 0);
//    tx->vin.emplace_back(input);
//
//    tx->vin.front().scriptWitness.stack.emplace_back(std::vector<unsigned char>(script.begin(), script.end()));
//
////
////    CScript inpubkeyscript;
////    inpubkeyscript << 0;
////    inpubkeyscript << scripthash;
////
////    MutableTransactionSignatureChecker sigChecker(&tx, 0, amount);
////    ScriptError error;
////    unsigned flags = SCRIPT_VERIFY_NULLDUMMY | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
////    bool txres = VerifyScript(CScript(), inpubkeyscript, &(tx.vin[0].scriptWitness), flags, sigChecker, &error);
////    if(!txres)
////    {
////        throw std::runtime_error(ScriptErrorString(error));
////    }
////
//    return tx;
//}

std::string ChainApi::TestTxSequence(const std::vector<CMutableTransaction>& txs) const
{
    std::ostringstream tx_to_param;
    bool first = true;

    tx_to_param << "[";
    for(const auto& tx: txs)
    {
        //Log(tx);

        if(first) first = false;
        else tx_to_param << ',';

        tx_to_param << "\"" << EncodeHexTx(CTransaction(tx)) << "\"";
    }
    tx_to_param << "]";

    return Call(TESTMEMPOOLACCEPT, tx_to_param.str());
}

std::string ChainApi::SpendTx(const CTransaction &tx) const
{
    return Call(SENDRAWTRANSACTION, EncodeHexTx(tx));
}

CTransaction ChainApi::GetTx(std::string txid) const
{
    CMutableTransaction tx = Deserialize(Call(GETRAWTRANSACTION, move(txid)));
    return CTransaction(move(tx));
}

std::string ChainApi::SpendSegwitTx(CMutableTransaction &tx, const std::vector<bytevector> &witness_stack) const
{
    auto& witness = tx.vin[0].scriptWitness.stack;

    for(const auto& el: std::ranges::reverse_view(witness_stack))
    {
        witness.emplace_back(el);
    }

    //Log(tx);

    //--------------------------------------------------------------------------------------------------------------------------------------
    // script verification
    //--------------------------------------------------------------------------------------------------------------------------------------
//    if (nTransactions == 2)
//    {
//        std::vector<uint8_t> scripthash;
//        scripthash.resize(CSHA256::OUTPUT_SIZE);
//        //memset(scripthash, 0, CSHA256::OUTPUT_SIZE);
//        CSHA256().Write(tx.vin[0].scriptWitness.stack.back().data(), tx.vin[0].scriptWitness.stack.back().size()).Finalize(scripthash.data());
//
//        CScript scriptToVerify;
//        scriptToVerify << 0;
//        scriptToVerify << scripthash;
//
//        MutableTransactionSignatureChecker sigChecker(&tx, 0, ParseAmount("0.00016"), MissingDataBehavior::ASSERT_FAIL); // TO CALC EXACT VALUE( prev output)
//        ScriptError error;
//        //unsigned flags = SCRIPT_VERIFY_NULLDUMMY | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_MINIMALDATA;
//        unsigned flags = SCRIPT_VERIFY_NULLDUMMY | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_MINIMALDATA;
//        bool txres = VerifyScript(CScript(), scriptToVerify, &(tx.vin[0].scriptWitness), flags, sigChecker, &error);
//
//        if(!txres)
//        {
//            throw std::runtime_error(ScriptErrorString(error));
//        }
//        nTransactions = 0;
//    }
    
    //--------------------------------------------------------------------------------------------------------------------------------------

    return SpendTx(CTransaction(tx));
}

/**
 * ChainAPI::GetNewAddress() to obtain new bech32 address from node
 * 
 * Parameters:
 * -----------------------------------------------------------------------------------------
 * label - The label name for the address to be linked to. It can also be set to the empty string “” 
 * to represent the default label. The label does not need to exist, it will be created if there is no 
 * label by the given name
 * 
 * address_type - The address type to use. Options are “legacy”, “p2sh-segwit”, and “bech32”.
 * 
*/
std::string ChainApi::GetNewAddress(std::string label, std::string address_type) const
{
    return Call(GETNEWADDRESS, move(label), move(address_type));
}

std::string ChainApi::GenerateToAddress(std::string address, std::string nblocks) const
{
    return Call(GENERATETOADDRESS, move(nblocks), move(address));
}

void ChainApi::StopNode() const
{
    Call(STOP);
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

void ChainApi::CreateWallet(std::string name) const
{
    Call(CREATEWALLET, move(name));
}

std::string ChainApi::GetWalletInfo() const
{
    return Call(GETWALLETINFO);
}

void ChainApi::WalletPassPhrase(std::string phrase, std::string lifetime) const
{
    Call(WALLETPASSPHRASE, move(phrase), move(lifetime));
}

std::tuple<COutPoint, CTxOut> ChainApi::CheckOutput(const string& txid, const string& address) const
{
    std::string strTXOut;
    std::string txValue;

    int nout = 0;
    CAmount amount;
    CScript scriptPubKey;
    int attempts = 0;

    for(;attempts < 6; ++nout)
    {
        std::clog << "Checking output number " << nout << std::endl;

        strTXOut = GetTxOut(txid, std::to_string(nout));

        if(!strTXOut.empty())
        {
            //std::clog << strTXOut << std::endl;

            UniValue uniValues;
            uniValues.read(strTXOut);

            string a = uniValues["scriptPubKey"]["address"].getValStr();

            if(!a.empty() && a == address)
            {
                amount = ParseAmount(uniValues["value"].getValStr());

                bytevector scriptbytes = ParseHex(uniValues["scriptPubKey"]["hex"].getValStr());
                scriptPubKey = CScript(scriptbytes.begin(), scriptbytes.end());

                break;
            }
        }

        if(nout >= 2)
        {
            nout = -1;
            ++attempts;

            std::clog << "Waiting some time to allow bitcoin to process the transaction" << std::endl;

            std::this_thread::sleep_for(std::chrono::seconds(10));
        }
    }

    if (nout >= 2)
    {
        throw std::runtime_error(std::string("channel UTXO nout not found. txid=")+txid);
    }

    return { COutPoint(Txid::FromUint256(uint256S(txid)), nout), CTxOut(amount, scriptPubKey) };

}

std::string ChainApi::GetBlock(string block_hash, string verbosity) const
{
    return Call(GETBLOCK, move(block_hash), move(verbosity));
}

std::string ChainApi::GetZMQNotifications() const
{
    return Call(GETZMQNOTIFICATIONS);
}

std::string ChainApi::EstimateSmartFee(std::string confirmation_target, std::string mode) const
{
    std::string res = Call(ESTIMATESMARTFEE, move(confirmation_target), move(mode));

    UniValue resRoot;
    resRoot.read(res);

    if (resRoot.exists("feerate")) {
        return resRoot["feerate"].getValStr();
    }

    throw std::logic_error(resRoot["feerate"][0].getValStr());
}

}
