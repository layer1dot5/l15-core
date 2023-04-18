#include "chain_api.hpp"
#include "wallet_api.hpp"
#include "exechelper.hpp"

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
    ExecHelper check_connect(m_cli_path, false);

    std::for_each(m_default.cbegin(), m_default.cend(), [&check_connect](const std::string& v)
    {
        check_connect.Arguments().emplace_back(v);
    });

    check_connect.Arguments().emplace_back(GETBLOCKCOUNT);

    return std::stoul(check_connect.Run());
}

void ChainApi::CheckConnection() const
{
    GetChainHeight();
}

std::string ChainApi::SendToAddress(const std::string& address, const std::string& amount) const
{
    ExecHelper btc_exec(m_cli_path, false);

    std::for_each(m_default.cbegin(), m_default.cend(), [&btc_exec](const std::string& v)
    {
        btc_exec.Arguments().emplace_back(v);
    });

    btc_exec.Arguments().emplace_back(SENDTOADDRESS);
    btc_exec.Arguments().emplace_back(address);
    btc_exec.Arguments().emplace_back(amount);

    return std::regex_replace(btc_exec.Run(), sNewlineRegExp, "");
}


std::string ChainApi::GetTxOut(const std::string& txidhex, const std::string& out) const
{
    ExecHelper btc_exec(m_cli_path, false);

    std::for_each(m_default.cbegin(), m_default.cend(), [&btc_exec](const std::string& v)
    {
        btc_exec.Arguments().emplace_back(v);
    });

    btc_exec.Arguments().emplace_back(GETTXOUT);
    btc_exec.Arguments().emplace_back(txidhex);
    btc_exec.Arguments().emplace_back(out);

    return btc_exec.Run();
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
    for(const auto tx: txs)
    {
        //Log(tx);

        if(first) first = false;
        else tx_to_param << ',';

        tx_to_param << "\"" << EncodeHexTx(CTransaction(tx)) << "\"";
    }
    tx_to_param << "]";

    ExecHelper btc_exec(m_cli_path, false);

    for(const auto& v: m_default)
    {
        btc_exec.Arguments().push_back(v);
    }

    btc_exec.Arguments().emplace_back(TESTMEMPOOLACCEPT);
    btc_exec.Arguments().emplace_back(tx_to_param.str());

    return btc_exec.Run();
}

std::string ChainApi::SpendTx(const CTransaction &tx) const
{
    Log(tx);

    ExecHelper btc_exec(m_cli_path, false);

    for(const auto& v: m_default)
    {
        btc_exec.Arguments().push_back(v);
    }

    btc_exec.Arguments().emplace_back(SENDRAWTRANSACTION);
    btc_exec.Arguments().emplace_back(EncodeHexTx(tx));

    return btc_exec.Run();
}

std::string ChainApi::SpendSegwitTx(CMutableTransaction &tx, const std::vector<bytevector> &witness_stack) const
{
    auto& witness = tx.vin[0].scriptWitness.stack;
//    nTransactions++;

    for(auto I = witness_stack.crbegin(); I != witness_stack.crend(); ++I)
    {
        witness.emplace(witness.begin(), *I);
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
std::string ChainApi::GetNewAddress(const std::string& label, const std::string& address_type) const
{
    ExecHelper btc_exec(m_cli_path, false);

    std::for_each(m_default.cbegin(), m_default.cend(), [&btc_exec](const std::string& v)
    {
        btc_exec.Arguments().emplace_back(v);
    });

    btc_exec.Arguments().emplace_back(GETNEWADDRESS);
    btc_exec.Arguments().emplace_back(label);
    btc_exec.Arguments().emplace_back(address_type);

    return btc_exec.Run();
}

std::string ChainApi::GenerateToAddress(const std::string& address, const std::string &nblocks) const
{

    ExecHelper btc_exec(m_cli_path, false);

    std::for_each(m_default.cbegin(), m_default.cend(), [&btc_exec](const std::string& v)
    {
        btc_exec.Arguments().emplace_back(v);
    });

    btc_exec.Arguments().emplace_back(GENERATETOADDRESS);
    btc_exec.Arguments().emplace_back(nblocks);
    btc_exec.Arguments().emplace_back(address);

    return btc_exec.Run();
}

template <typename T>
void ChainApi::Log(const T& tx)
{
    std::clog << "Transaction " << tx.GetHash().GetHex() << " {\n"
        << "\tnLockTime: " << tx.nLockTime << "\n"
        << "\tvin {\n";
    bool first_in = true;
    for(const auto& in: tx.vin)
    {
        if(first_in) first_in = false;
        else std::clog << "\t\t------------------------------------------------\n";

        std::clog << "\t\t" << in.prevout.hash.GetHex() << " : "
                  << in.prevout.n << "\n"
                  << "\t\tWitness {\n";

        for(const auto& wel: in.scriptWitness.stack)
        {
            std::clog << "\t\t\t{" << HexStr(wel) << "}\n";
        }
        std::clog << "\t\t}\n";
    }
    std::clog << "\t}\n";

    std::clog << "\tvout {\n";
    bool first_out = true;
    for(const auto& out: tx.vout)
    {
        if(first_out) first_out = false;
        else std::clog << "\t\t------------------------------------------------\n";

        std::clog << "\t\tAmount: " << out.nValue << "\n";

        bytevector wp;
        int wver;
        if(out.scriptPubKey.IsWitnessProgram(wver, wp))
        {
            if(wver == 0 && wp.size() == 20) std::clog << "\t\tPubKeyHash Witness program: "  << HexStr(wp) << "\n";
            else if (wver == 0 && wp.size() == 32) std::clog << "\t\tScriptHash Witness program: " << HexStr(wp) << "\n";
            else std::clog << "\t\tWitness program v" << wver << ": " << HexStr(wp) << "\n";
        } else
        {
            std::clog << "\t\tScriptPubKey: "<< HexStr(out.scriptPubKey) << "\n";
        }

    }
    std::clog << "\t}\n}" << std::endl;
}

template void ChainApi::Log<CTransaction>(const CTransaction& );
template void ChainApi::Log<CMutableTransaction>(const CMutableTransaction& );


void ChainApi::StopNode() const
{
    ExecHelper btc_exec(m_cli_path, false);
    std::for_each(m_default.cbegin(), m_default.cend(), [&btc_exec](const std::string& v)
    {
        btc_exec.Arguments().emplace_back(v);
    });

    btc_exec.Arguments().emplace_back(STOP);

    btc_exec.Run();

    std::this_thread::sleep_for(std::chrono::seconds(1));
}

void ChainApi::CreateWallet(std::string&& name) const
{
    ExecHelper btc_exec(m_cli_path, false);
    std::for_each(m_default.cbegin(), m_default.cend(), [&btc_exec](const std::string& v)
    {
        btc_exec.Arguments().emplace_back(v);
    });

    btc_exec.Arguments().emplace_back(CREATEWALLET);
    btc_exec.Arguments().emplace_back(name);

    btc_exec.Run();
}

std::string ChainApi::GetWalletInfo() const
{
    ExecHelper btc_exec(m_cli_path, false);
    std::for_each(m_default.cbegin(), m_default.cend(), [&btc_exec](const std::string& v)
    {
        btc_exec.Arguments().emplace_back(v);
    });

    btc_exec.Arguments().emplace_back(GETWALLETINFO);

    return btc_exec.Run();
}

void ChainApi::WalletPassPhrase(const std::string& phrase, const std::string& lifetime) const
{
    ExecHelper btc_exec(m_cli_path, false);
    std::for_each(m_default.cbegin(), m_default.cend(), [&btc_exec](const std::string& v)
    {
        btc_exec.Arguments().emplace_back(v);
    });

    btc_exec.Arguments().emplace_back(WALLETPASSPHRASE);
    btc_exec.Arguments().emplace_back(phrase);
    btc_exec.Arguments().emplace_back(lifetime);

    btc_exec.Run();
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

    return { COutPoint(uint256S(txid), nout), CTxOut(amount, scriptPubKey) };

}

std::string ChainApi::GetBlock(const string &block_hash, const string &verbosity) const
{
    ExecHelper btc_exec(m_cli_path, false);
    std::for_each(m_default.cbegin(), m_default.cend(), [&btc_exec](const std::string& v)
    {
        btc_exec.Arguments().emplace_back(v);
    });

    btc_exec.Arguments().emplace_back(GETBLOCK);
    btc_exec.Arguments().emplace_back(block_hash);
    btc_exec.Arguments().emplace_back(verbosity);

    return btc_exec.Run();
}

std::string ChainApi::GetZMQNotifications() const
{
    ExecHelper btc_exec(m_cli_path, false);
    std::for_each(m_default.cbegin(), m_default.cend(), [&btc_exec](const std::string& v)
    {
        btc_exec.Arguments().emplace_back(v);
    });

    btc_exec.Arguments().emplace_back(GETZMQNOTIFICATIONS);

    return btc_exec.Run();
}

std::string ChainApi::EstimateSmartFee(const std::string& confirmation_target, const std::string& mode) const
{
    ExecHelper btc_exec(m_cli_path, false);
    std::for_each(m_default.cbegin(), m_default.cend(), [&btc_exec](const std::string& v)
    {
        btc_exec.Arguments().emplace_back(v);
    });

    btc_exec.Arguments().emplace_back(ESTIMATESMARTFEE);
    btc_exec.Arguments().emplace_back(confirmation_target);
    btc_exec.Arguments().emplace_back(mode);


    std::string res = btc_exec.Run();

    UniValue resRoot;
    resRoot.read(res);

    if (resRoot.exists("feerate")) {
        return resRoot["feerate"].getValStr();
    }
    else {
        throw std::logic_error(resRoot["feerate"][0].getValStr());
    }
}

}
