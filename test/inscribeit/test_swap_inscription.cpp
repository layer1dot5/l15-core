#include <iostream>
#include <filesystem>
#include <algorithm>

#define CATCH_CONFIG_RUNNER
#include "catch/catch.hpp"

#include "util/translation.h"
#include "config.hpp"
#include "nodehelper.hpp"
#include "chain_api.hpp"
#include "wallet_api.hpp"
#include "channel_keys.hpp"
#include "exechelper.hpp"
#include "swap_inscription.hpp"
#include "core_io.h"
#include "serialize.h"
#include "hash.h"

using namespace l15;
using namespace l15::core;
using namespace l15::inscribeit;

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

class TestcaseWrapper;

std::string configpath;
std::unique_ptr<TestcaseWrapper> w;

struct TestConfigFactory
{
    Config conf;

    explicit TestConfigFactory(const std::string &confpath)
    {
        conf.ProcessConfig({"--conf=" + confpath});
    }

    std::string GetBitcoinDataDir() const
    {
        auto datadir_opt = conf.Subcommand(config::BITCOIND).get_option(config::option::DATADIR);
        if(!datadir_opt->empty())
            return datadir_opt->as<std::string>();
        else
            return std::string();
    }
};

struct TestcaseWrapper
{
    TestConfigFactory mConfFactory;
    WalletApi mWallet;
    ChainApi mBtc;
    ExecHelper mCli;
    ExecHelper mBtcd;

    explicit TestcaseWrapper() :
            mConfFactory(configpath),
            mWallet(),
            mBtc(Bech32Coder<IBech32Coder::BTC, IBech32Coder::REGTEST>(), std::move(mConfFactory.conf.ChainValues(config::BITCOIN)), "l15node-cli"),
            mCli("l15node-cli", false),
            mBtcd("bitcoind", false)

    {
        StartBitcoinNode();

        if(btc().GetChainHeight() < 50)
        {
            btc().CreateWallet("testwallet");
            btc().GenerateToAddress(btc().GetNewAddress(), "250");
        }
    }

    virtual ~TestcaseWrapper()
    {
        StopBitcoinNode();
        std::filesystem::remove_all(mConfFactory.GetBitcoinDataDir() + "/regtest");
    }

    void StartBitcoinNode()
    {
        StartNode(ChainMode::MODE_REGTEST, mBtcd, conf().Subcommand(config::BITCOIND));
    }

    void StopBitcoinNode()
    {
        StopNode(ChainMode::MODE_REGTEST, mCli, conf().Subcommand(config::BITCOIN));
    }

    Config &conf()
    { return mConfFactory.conf; }

    WalletApi &wallet()
    { return mWallet; }

    ChainApi &btc()
    { return mBtc; }

    void ResetMemPool()
    {
        StopBitcoinNode();
        std::filesystem::remove(mConfFactory.GetBitcoinDataDir() + "/regtest/mempool.dat");
        StartBitcoinNode();
    }

};

int main(int argc, char* argv[])
{
    Catch::Session session;


    // Build a new parser on top of Catch's
    using namespace Catch::clara;
    auto cli
            = session.cli() // Get Catch's composite command line parser
              | Opt(configpath, "Config path") // bind variable to a new option, with a hint string
              ["--config"]    // the option names it will respond to
                      ("Path to L15 config");

    session.cli(cli);

    // Let Catch (using Clara) parse the command line
    int returnCode = session.applyCommandLine(argc, argv);
    if(returnCode != 0) // Indicates a command line error
        return returnCode;

    if(configpath.empty())
    {
        std::cerr << "Bitcoin config is not passed!" << std::endl;
        return 1;
    }

    std::filesystem::path p(configpath);
    if(p.is_relative())
    {
        configpath = (std::filesystem::current_path() / p).string();
    }

    w = std::make_unique<TestcaseWrapper>();

    return session.run();
}



TEST_CASE("SwapInscriptionBuilder positive scenario with setters")
{
    ChannelKeys swap_script_key_A;
    ChannelKeys swap_script_key_B;
    ChannelKeys swap_script_key_M;
    seckey preimage = ChannelKeys::GetStrongRandomKey();
    seckey ord_unspendable_factor = ChannelKeys::GetStrongRandomKey();
    seckey funds_unspendable_factor = ChannelKeys::GetStrongRandomKey();
    bytevector swap_hash(32);
    CHash256().Write(preimage).Finalize(swap_hash);


    //get key pair
    ChannelKeys ord_utxo_key;
    ChannelKeys funds_utxo_key;

    //Create ord utxo
    string ord_addr = w->btc().Bech32Encode(ord_utxo_key.GetLocalPubKey());
    string ord_txid = w->btc().SendToAddress(ord_addr, "0.00001");
    auto ord_prevout = w->btc().CheckOutput(ord_txid, ord_addr);

    //Create funds utxo
    string funds_addr = w->btc().Bech32Encode(funds_utxo_key.GetLocalPubKey());
    string funds_txid = w->btc().SendToAddress(funds_addr, "1");
    auto funds_prevout = w->btc().CheckOutput(funds_txid, funds_addr);

    //CHECK_NOTHROW(fee_rate = w->btc().EstimateSmartFee("1"));
    std::string fee_rate = "0.00001";
    //std::clog << "Fee rate: " << fee_rate << std::endl;

    SwapInscriptionBuilder builderOrdSeller("regtest");
    builderOrdSeller.SetOrdUnspendableKeyFactor(hex(ord_unspendable_factor));
    builderOrdSeller.SetMiningFeeRate(fee_rate);
    builderOrdSeller.SetSwapScriptPubKeyM(hex(swap_script_key_M.GetLocalPubKey()));
    builderOrdSeller.SetSwapScriptPubKeyA(hex(swap_script_key_A.GetLocalPubKey()));

    SwapInscriptionBuilder builderOrdBuyer("regtest");
    builderOrdBuyer.SetFundsUnspendableKeyFactor(hex(funds_unspendable_factor));
    builderOrdBuyer.SetMiningFeeRate(fee_rate);
    builderOrdBuyer.SetSwapScriptPubKeyM(hex(swap_script_key_M.GetLocalPubKey()));
    builderOrdBuyer.SetSwapScriptPubKeyB(hex(swap_script_key_B.GetLocalPubKey()));
    builderOrdBuyer.SetSwapHash(hex(swap_hash));


    //Exchange Commit UTXO
    //---------------------

    builderOrdSeller.SetOrdUtxoTxId(get<0>(ord_prevout).hash.GetHex());
    builderOrdSeller.SetOrdUtxoNOut(get<0>(ord_prevout).n);
    builderOrdSeller.SetOrdUtxoAmount("0.00001");
    builderOrdSeller.SignOrdUtxo(hex(ord_utxo_key.GetLocalPrivKey()));
    std::string ord_commit_raw_tx;
    CHECK_NOTHROW(ord_commit_raw_tx = builderOrdSeller.OrdCommitRawTransaction());

    builderOrdBuyer.SetFundsUtxoTxId(get<0>(funds_prevout).hash.GetHex());
    builderOrdBuyer.SetFundsUtxoNOut(get<0>(funds_prevout).n);
    builderOrdBuyer.SetFundsUtxoAmount("1");
    builderOrdBuyer.SignFundsUtxo(hex(funds_utxo_key.GetLocalPrivKey()));
    std::string funds_commit_raw_tx;
    CHECK_NOTHROW(funds_commit_raw_tx = builderOrdBuyer.FundsCommitRawTransaction());

//    CHECK_NOTHROW(builderOrdBuyer.Deserialize(ord_commit_data));
//    CHECK_NOTHROW(builderOrdSeller.Deserialize(funds_commit_data));
//
//    std::string ord_commit_raw_tx, funds_commit_raw_tx;
//    CHECK_NOTHROW(ord_commit_raw_tx = builderOrdBuyer.OrdCommitRawTransaction());
//    CHECK_NOTHROW(funds_commit_raw_tx = builderOrdBuyer.FundsCommitRawTransaction());
//
//    std::string ord_commit_raw_tx1, funds_commit_raw_tx1;
//    CHECK_NOTHROW(ord_commit_raw_tx1 = builderOrdSeller.OrdCommitRawTransaction());
//    CHECK_NOTHROW(funds_commit_raw_tx1 = builderOrdSeller.FundsCommitRawTransaction());
//
//    CHECK(ord_commit_raw_tx == ord_commit_raw_tx1);
//    CHECK(funds_commit_raw_tx == funds_commit_raw_tx1);
//
    CMutableTransaction ord_commit_tx, funds_commit_tx;
    CHECK(DecodeHexTx(ord_commit_tx, ord_commit_raw_tx));
    CHECK(DecodeHexTx(funds_commit_tx, funds_commit_raw_tx));

    CHECK_NOTHROW(w->btc().SpendTx(CTransaction(ord_commit_tx)));
    CHECK_NOTHROW(w->btc().SpendTx(CTransaction(funds_commit_tx)));


//    builder.SetDestinationPubKey(hex(dest_key.GetLocalPubKey()));
//
//    CHECK_NOTHROW(builder.Sign(hex(utxo_key.GetLocalPrivKey())));
//
//    std::string ser_data;
//    CHECK_NOTHROW(ser_data = builder.Serialize());
//
//    std::clog << ser_data << std::endl;
//
//    CreateInscriptionBuilder builder2("regtest");
//
//    CHECK_NOTHROW(builder2.Deserialize(ser_data));
//
//    stringvector rawtx;
//    CHECK_NOTHROW(rawtx = builder2.RawTransactions());
//
//    CMutableTransaction funding_tx, genesis_tx;
//    CHECK(DecodeHexTx(funding_tx, rawtx.front()));
//    CHECK(DecodeHexTx(genesis_tx, rawtx.back()));
//
//    CHECK_NOTHROW(w->btc().SpendTx(CTransaction(funding_tx)));
//    CHECK_NOTHROW(w->btc().SpendTx(CTransaction(genesis_tx)));
}

