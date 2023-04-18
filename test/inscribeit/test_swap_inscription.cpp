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

#include "policy/policy.h"

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
            btc().GenerateToAddress(btc().GetNewAddress(), "150");
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



TEST_CASE("OrdPayBack")
{
    ChannelKeys swap_script_key_A;
    ChannelKeys swap_script_key_M;
    seckey ord_unspendable_factor = ChannelKeys::GetStrongRandomKey();
    seckey funds_unspendable_factor = ChannelKeys::GetStrongRandomKey();

    //get key pair
    ChannelKeys ord_utxo_key;

    //Create ord utxo
    string ord_addr = w->btc().Bech32Encode(ord_utxo_key.GetLocalPubKey());
    string ord_txid = w->btc().SendToAddress(ord_addr, "0.000025");
    auto ord_prevout = w->btc().CheckOutput(ord_txid, ord_addr);

    std::string fee_rate = "0.000015";

    SwapInscriptionBuilder builderOrdSeller("regtest", "0.1", "0.01");
    builderOrdSeller.SetOrdCommitMiningFeeRate(fee_rate);
    builderOrdSeller.SetSwapScriptPubKeyM(hex(swap_script_key_M.GetLocalPubKey()));
    builderOrdSeller.SetSwapScriptPubKeyA(hex(swap_script_key_A.GetLocalPubKey()));

    //Exchange Commit UTXO
    //---------------------

    builderOrdSeller.OrdUTXO(get<0>(ord_prevout).hash.GetHex(), get<0>(ord_prevout).n, "0.000025");
    REQUIRE_NOTHROW(builderOrdSeller.SignOrdCommitment(hex(ord_utxo_key.GetLocalPrivKey())));
    std::string ord_commit_raw_tx;
    REQUIRE_NOTHROW(ord_commit_raw_tx = builderOrdSeller.OrdCommitRawTransaction());


    CMutableTransaction ord_commit_tx;
    REQUIRE(DecodeHexTx(ord_commit_tx, ord_commit_raw_tx));

    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_commit_tx)));


    REQUIRE_NOTHROW(builderOrdSeller.SignOrdPayBack(hex(swap_script_key_A.GetLocalPrivKey())));
    std::string ord_payback_raw_tx;
    REQUIRE_NOTHROW(ord_payback_raw_tx = builderOrdSeller.OrdPayBackRawTransaction());

    CMutableTransaction ord_payback_tx;
    REQUIRE(DecodeHexTx(ord_payback_tx, ord_payback_raw_tx));

    w->btc().GenerateToAddress(w->btc().GetNewAddress(), "11");
    REQUIRE_THROWS(w->btc().SpendTx(CTransaction(ord_payback_tx)));
    w->btc().GenerateToAddress(w->btc().GetNewAddress(), "1");
    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_payback_tx)));
}


TEST_CASE("FundsPayBack")
{
    ChannelKeys swap_script_key_B;
    ChannelKeys swap_script_key_M;
    seckey unspendable_factor = ChannelKeys::GetStrongRandomKey();

    //get key pair
    ChannelKeys funds_utxo_key;

    //Create ord utxo
    string funds_addr = w->btc().Bech32Encode(funds_utxo_key.GetLocalPubKey());
    string funds_txid = w->btc().SendToAddress(funds_addr, "0.15");
    auto funds_prevout = w->btc().CheckOutput(funds_txid, funds_addr);

    std::string fee_rate = "0.000015";

    SwapInscriptionBuilder builderOrdBuyer("regtest", "0.1", "0.01");
    builderOrdBuyer.SetMiningFeeRate(fee_rate);
    builderOrdBuyer.SetOrdCommitMiningFeeRate(fee_rate);
    builderOrdBuyer.SetSwapScriptPubKeyM(hex(swap_script_key_M.GetLocalPubKey()));
    builderOrdBuyer.SetSwapScriptPubKeyB(hex(swap_script_key_B.GetLocalPubKey()));

    //Exchange Commit UTXO
    //---------------------

    builderOrdBuyer.FundsUTXO(get<0>(funds_prevout).hash.GetHex(), get<0>(funds_prevout).n, "0.15");
    REQUIRE_NOTHROW(builderOrdBuyer.SignFundsCommitment(hex(funds_utxo_key.GetLocalPrivKey())));
    std::string funds_commit_raw_tx;
    REQUIRE_NOTHROW(funds_commit_raw_tx = builderOrdBuyer.FundsCommitRawTransaction());


    CMutableTransaction funds_commit_tx;
    REQUIRE(DecodeHexTx(funds_commit_tx, funds_commit_raw_tx));

    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(funds_commit_tx)));


    REQUIRE_NOTHROW(builderOrdBuyer.SignFundsPayBack(hex(swap_script_key_B.GetLocalPrivKey())));
    std::string funds_payback_raw_tx;
    REQUIRE_NOTHROW(funds_payback_raw_tx = builderOrdBuyer.FundsPayBackRawTransaction());

    CMutableTransaction funds_payback_tx;
    REQUIRE(DecodeHexTx(funds_payback_tx, funds_payback_raw_tx));

    w->btc().GenerateToAddress(w->btc().GetNewAddress(), "11");
    REQUIRE_THROWS(w->btc().SpendTx(CTransaction(funds_payback_tx)));
    w->btc().GenerateToAddress(w->btc().GetNewAddress(), "1");
    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(funds_payback_tx)));

}

TEST_CASE("FullSwap")
{
    const std::string funds_amount = "0.11008000";
    ChannelKeys swap_script_key_A;
    ChannelKeys swap_script_key_B;
    ChannelKeys swap_script_key_M;
    //get key pair
    ChannelKeys ord_utxo_key;
    ChannelKeys funds_utxo_key;

    //CHECK_NOTHROW(fee_rate = w->btc().EstimateSmartFee("1"));
    std::string fee_rate = "0.000015";
    //std::clog << "Fee rate: " << fee_rate << std::endl;

    // ORD side terms
    //--------------------------------------------------------------------------

    SwapInscriptionBuilder builderMarket("regtest", "0.1", "0.01");
    builderMarket.SetOrdCommitMiningFeeRate(fee_rate);
    builderMarket.SetMiningFeeRate(fee_rate);
    builderMarket.SetSwapScriptPubKeyM(hex(swap_script_key_M.GetLocalPubKey()));

    string marketOrdConditions = builderMarket.Serialize(SwapInscriptionBuilder::OrdTerms);

    SwapInscriptionBuilder builderOrdSeller("regtest", "0.1", "0.01");
    builderOrdSeller.Deserialize(marketOrdConditions);

    builderOrdSeller.CheckContractTerms(SwapInscriptionBuilder::OrdTerms);

    //Create ord utxo
    string ord_addr = w->btc().Bech32Encode(ord_utxo_key.GetLocalPubKey());
    string ord_txid = w->btc().SendToAddress(ord_addr, "0.000025");
    auto ord_prevout = w->btc().CheckOutput(ord_txid, ord_addr);

    builderOrdSeller.OrdUTXO(get<0>(ord_prevout).hash.GetHex(), get<0>(ord_prevout).n, "0.000025");
    builderOrdSeller.SetSwapScriptPubKeyA(hex(swap_script_key_A.GetLocalPubKey()));

    REQUIRE_NOTHROW(builderOrdSeller.SignOrdCommitment(hex(ord_utxo_key.GetLocalPrivKey())));
    REQUIRE_NOTHROW(builderOrdSeller.SignOrdSwap(hex(swap_script_key_A.GetLocalPrivKey())));

    string ordSellerTerms = builderOrdSeller.Serialize(SwapInscriptionBuilder::OrdSwapSig);


    // FUNDS side terms
    //--------------------------------------------------------------------------

    //builderMarket.SetMiningFeeRate(fee_rate);
    string marketFundsConditions = builderMarket.Serialize(SwapInscriptionBuilder::FundsTerms);

    SwapInscriptionBuilder builderOrdBuyer("regtest", "0.1", "0.01");
    builderOrdBuyer.Deserialize(marketFundsConditions);

    //Create funds utxo
    string funds_addr = w->btc().Bech32Encode(funds_utxo_key.GetLocalPubKey());
    string funds_txid = w->btc().SendToAddress(funds_addr, funds_amount);
    auto funds_prevout = w->btc().CheckOutput(funds_txid, funds_addr);

    builderOrdBuyer.FundsUTXO(get<0>(funds_prevout).hash.GetHex(), get<0>(funds_prevout).n, funds_amount);
    builderOrdBuyer.SetSwapScriptPubKeyB(hex(swap_script_key_B.GetLocalPubKey()));
    REQUIRE_NOTHROW(builderOrdBuyer.SignFundsCommitment(hex(funds_utxo_key.GetLocalPrivKey())));

    string ordBuyerTerms = builderOrdBuyer.Serialize(SwapInscriptionBuilder::FundsCommitSig);


    // MARKET confirm terms
    //--------------------------------------------------------------------------

    builderMarket.Deserialize(ordSellerTerms);
    builderMarket.Deserialize(ordBuyerTerms);

    string funds_commit_raw_tx = builderMarket.FundsCommitRawTransaction();
    string ord_commit_raw_tx = builderMarket.OrdCommitRawTransaction();

    CMutableTransaction ord_commit_tx, funds_commit_tx;
    REQUIRE(DecodeHexTx(ord_commit_tx, ord_commit_raw_tx));
    REQUIRE(DecodeHexTx(funds_commit_tx, funds_commit_raw_tx));

    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(funds_commit_tx)));
    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_commit_tx)));

    w->btc().GenerateToAddress(w->btc().GetNewAddress(), "1");

    REQUIRE_NOTHROW(builderMarket.MarketSignOrdPayoffTx(hex(swap_script_key_M.GetLocalPrivKey())));
    string ordMarketTerms = builderMarket.Serialize(SwapInscriptionBuilder::MarketPayoffSig);


    // BUYER sign swap
    //--------------------------------------------------------------------------

    builderOrdBuyer.Deserialize(ordMarketTerms);
    REQUIRE_NOTHROW(builderOrdBuyer.SignFundsSwap(hex(swap_script_key_B.GetLocalPrivKey())));

    string ordFundsSignature = builderOrdBuyer.Serialize(SwapInscriptionBuilder::FundsSwapSig);


    // MARKET sign swap
    //--------------------------------------------------------------------------

    builderMarket.Deserialize(ordFundsSignature);
    REQUIRE_NOTHROW(builderMarket.MarketSignSwap(hex(swap_script_key_M.GetLocalPrivKey())));

    string ord_swap_raw_tx = builderMarket.OrdSwapRawTransaction();
    string ord_transfer_raw_tx = builderMarket.OrdPayoffRawTransaction();

    CMutableTransaction ord_swap_tx, ord_transfer_tx;
    REQUIRE(DecodeHexTx(ord_swap_tx, ord_swap_raw_tx));
    REQUIRE(DecodeHexTx(ord_transfer_tx, ord_transfer_raw_tx));

    PrecomputedTransactionData txdata;
    txdata.Init(ord_swap_tx, {ord_commit_tx.vout[0], funds_commit_tx.vout[0]}, /* force=*/ true);

    const CTxIn& ordTxin = ord_swap_tx.vin.at(0);
    MutableTransactionSignatureChecker TxOrdChecker(&ord_swap_tx, 0, ord_commit_tx.vout[0].nValue, txdata, MissingDataBehavior::FAIL);
    bool ordPath = VerifyScript(ordTxin.scriptSig, ord_commit_tx.vout[0].scriptPubKey, &ordTxin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TxOrdChecker);
    REQUIRE(ordPath);

    const CTxIn& txin = ord_swap_tx.vin.at(1);
    MutableTransactionSignatureChecker tx_checker(&ord_swap_tx, 1, funds_commit_tx.vout[0].nValue, txdata, MissingDataBehavior::FAIL);
    bool fundsPath = VerifyScript(txin.scriptSig, funds_commit_tx.vout[0].scriptPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, tx_checker);
    REQUIRE(fundsPath);

    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_swap_tx)));
    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_transfer_tx)));

    w->btc().GenerateToAddress(w->btc().GetNewAddress(), "1");


    // BUYER spends his ord
    //--------------------------------------------------------------------------

    xonly_pubkey payoff_pk = w->btc().Bech32Decode(w->btc().GetNewAddress());
    CScript buyer_pubkeyscript = CScript() << 1 << payoff_pk;


    CMutableTransaction ord_payoff_tx;
    ord_payoff_tx.vin = {CTxIn(ord_transfer_tx.GetHash(), 0)};
    ord_payoff_tx.vin.front().scriptWitness.stack.emplace_back(64);
    ord_payoff_tx.vout = {CTxOut(ord_transfer_tx.vout[0].nValue, buyer_pubkeyscript)};
    ord_payoff_tx.vout.front().nValue = CalculateOutputAmount(ord_transfer_tx.vout[0].nValue, ParseAmount(fee_rate), ord_payoff_tx);

    REQUIRE_NOTHROW(ord_payoff_tx.vin.front().scriptWitness.stack[0] = swap_script_key_B.SignTaprootTx(ord_payoff_tx, 0, {ord_transfer_tx.vout[0]}, {}));

    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_payoff_tx)));

    w->btc().GenerateToAddress(w->btc().GetNewAddress(), "1");

    // MARKET tries to spend buyer's change
    //--------------------------------------------------------------------------

    xonly_pubkey change_pk = w->btc().Bech32Decode(w->btc().GetNewAddress());
    CScript buyer_change_pubkey_script = CScript() << 1 << change_pk;

    CMutableTransaction ord_change_spend_tx;
    ord_change_spend_tx.vin = {CTxIn(funds_commit_tx.GetHash(), 1)};
    ord_change_spend_tx.vin.front().scriptWitness.stack.emplace_back(64);
    ord_change_spend_tx.vout = {CTxOut(funds_commit_tx.vout[1].nValue, buyer_change_pubkey_script)};
    ord_change_spend_tx.vout.front().nValue = CalculateOutputAmount(funds_commit_tx.vout[1].nValue, ParseAmount(fee_rate), ord_change_spend_tx);

    REQUIRE_NOTHROW(ord_change_spend_tx.vin.front().scriptWitness.stack[0] = swap_script_key_M.SignTaprootTx(ord_change_spend_tx, 0, {funds_commit_tx.vout[1]}, {}));

    REQUIRE_THROWS(w->btc().SpendTx(CTransaction(ord_change_spend_tx)));

    // BUYER spends his change
    //--------------------------------------------------------------------------

    REQUIRE_NOTHROW(ord_change_spend_tx.vin.front().scriptWitness.stack[0] = swap_script_key_B.SignTaprootTx(ord_change_spend_tx, 0, {funds_commit_tx.vout[1]}, {}));

    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_change_spend_tx)));

    w->btc().GenerateToAddress(w->btc().GetNewAddress(), "1");
}

TEST_CASE("FullSwapNoChange")
{
    const std::string funds_amount = "0.11000720";
    ChannelKeys swap_script_key_A;
    ChannelKeys swap_script_key_B;
    ChannelKeys swap_script_key_M;
    seckey preimage = ChannelKeys::GetStrongRandomKey();
    bytevector swap_hash(32);
    CHash256().Write(preimage).Finalize(swap_hash);
    //get key pair
    ChannelKeys ord_utxo_key;
    ChannelKeys funds_utxo_key;

    //CHECK_NOTHROW(fee_rate = w->btc().EstimateSmartFee("1"));
    std::string fee_rate = "0.000015";
    //std::clog << "Fee rate: " << fee_rate << std::endl;

    // ORD side terms
    //--------------------------------------------------------------------------

    SwapInscriptionBuilder builderMarket("regtest", "0.1", "0.01");
    builderMarket.SetOrdCommitMiningFeeRate(fee_rate);
    builderMarket.SetMiningFeeRate(fee_rate);
    builderMarket.SetSwapScriptPubKeyM(hex(swap_script_key_M.GetLocalPubKey()));

    string marketOrdConditions = builderMarket.Serialize(SwapInscriptionBuilder::OrdTerms);

    SwapInscriptionBuilder builderOrdSeller("regtest", "0.1", "0.01");
    builderOrdSeller.Deserialize(marketOrdConditions);

    builderOrdSeller.CheckContractTerms(SwapInscriptionBuilder::OrdTerms);

    //Create ord utxo
    string ord_addr = w->btc().Bech32Encode(ord_utxo_key.GetLocalPubKey());
    string ord_txid = w->btc().SendToAddress(ord_addr, "0.000025");
    auto ord_prevout = w->btc().CheckOutput(ord_txid, ord_addr);

    builderOrdSeller.SetSwapScriptPubKeyA(hex(swap_script_key_A.GetLocalPubKey()));
    builderOrdSeller.OrdUTXO(get<0>(ord_prevout).hash.GetHex(), get<0>(ord_prevout).n, "0.000025");

    REQUIRE_NOTHROW(builderOrdSeller.SignOrdCommitment(hex(ord_utxo_key.GetLocalPrivKey())));
    REQUIRE_NOTHROW(builderOrdSeller.SignOrdSwap(hex(swap_script_key_A.GetLocalPrivKey())));

    string ordSellerTerms = builderOrdSeller.Serialize(SwapInscriptionBuilder::OrdSwapSig);


    // FUNDS side terms
    //--------------------------------------------------------------------------

    //builderMarket.SetMiningFeeRate(fee_rate);
    string marketFundsConditions = builderMarket.Serialize(SwapInscriptionBuilder::FundsTerms);

    SwapInscriptionBuilder builderOrdBuyer("regtest", "0.1", "0.01");
    builderOrdBuyer.Deserialize(marketFundsConditions);

    //Create funds utxo
    string funds_addr = w->btc().Bech32Encode(funds_utxo_key.GetLocalPubKey());
    string funds_txid = w->btc().SendToAddress(funds_addr, funds_amount);
    auto funds_prevout = w->btc().CheckOutput(funds_txid, funds_addr);

    builderOrdBuyer.SetSwapScriptPubKeyB(hex(swap_script_key_B.GetLocalPubKey()));
    builderOrdBuyer.FundsUTXO(get<0>(funds_prevout).hash.GetHex(), get<0>(funds_prevout).n, funds_amount);
    REQUIRE_THROWS_AS(builderOrdBuyer.SignFundsCommitment(hex(funds_utxo_key.GetLocalPrivKey())), l15::TransactionError);
}

TEST_CASE("FullSwapFee")
{
    const std::string funds_amount = "0.11008000";
    ChannelKeys swap_script_key_A;
    ChannelKeys swap_script_key_B;
    ChannelKeys swap_script_key_M;
    //get key pair
    ChannelKeys ord_utxo_key;
    ChannelKeys funds_utxo_key;

    //CHECK_NOTHROW(fee_rate = w->btc().EstimateSmartFee("1"));
    std::string fee_rate = "0.000015";
    std::string ord_fee_rate = "0.000030";
    //std::clog << "Fee rate: " << fee_rate << std::endl;

    // ORD side terms
    //--------------------------------------------------------------------------

    SwapInscriptionBuilder builderMarket("regtest", "0.1", "0.01");
    builderMarket.SetOrdCommitMiningFeeRate(ord_fee_rate);
    builderMarket.SetMiningFeeRate(fee_rate);
    builderMarket.SetSwapScriptPubKeyM(hex(swap_script_key_M.GetLocalPubKey()));

    string marketOrdConditions = builderMarket.Serialize(SwapInscriptionBuilder::OrdTerms);

    SwapInscriptionBuilder builderOrdSeller("regtest", "0.1", "0.01");
    builderOrdSeller.Deserialize(marketOrdConditions);

    builderOrdSeller.CheckContractTerms(SwapInscriptionBuilder::OrdTerms);

    //Create ord utxo
    string ord_addr = w->btc().Bech32Encode(ord_utxo_key.GetLocalPubKey());
    string ord_txid = w->btc().SendToAddress(ord_addr, "0.000025");
    auto ord_prevout = w->btc().CheckOutput(ord_txid, ord_addr);

    builderOrdSeller.SetSwapScriptPubKeyA(hex(swap_script_key_A.GetLocalPubKey()));
    builderOrdSeller.OrdUTXO(get<0>(ord_prevout).hash.GetHex(), get<0>(ord_prevout).n, "0.000025");

    REQUIRE_NOTHROW(builderOrdSeller.SignOrdCommitment(hex(ord_utxo_key.GetLocalPrivKey())));
    REQUIRE_NOTHROW(builderOrdSeller.SignOrdSwap(hex(swap_script_key_A.GetLocalPrivKey())));

    string ordSellerTerms = builderOrdSeller.Serialize(SwapInscriptionBuilder::OrdSwapSig);


    // FUNDS side terms
    //--------------------------------------------------------------------------

    //builderMarket.SetMiningFeeRate(fee_rate);
    string marketFundsConditions = builderMarket.Serialize(SwapInscriptionBuilder::FundsTerms);

    SwapInscriptionBuilder builderOrdBuyer("regtest", "0.1", "0.01");
    builderOrdBuyer.Deserialize(marketFundsConditions);

    //Create funds utxo
    string funds_addr = w->btc().Bech32Encode(funds_utxo_key.GetLocalPubKey());
    string funds_txid = w->btc().SendToAddress(funds_addr, funds_amount);
    auto funds_prevout = w->btc().CheckOutput(funds_txid, funds_addr);

    builderOrdBuyer.SetSwapScriptPubKeyB(hex(swap_script_key_B.GetLocalPubKey()));
    builderOrdBuyer.FundsUTXO(get<0>(funds_prevout).hash.GetHex(), get<0>(funds_prevout).n, funds_amount);
    REQUIRE_NOTHROW(builderOrdBuyer.SignFundsCommitment(hex(funds_utxo_key.GetLocalPrivKey())));

    string ordBuyerTerms = builderOrdBuyer.Serialize(SwapInscriptionBuilder::FundsCommitSig);


    // MARKET confirm terms
    //--------------------------------------------------------------------------

    builderMarket.Deserialize(ordSellerTerms);
    builderMarket.Deserialize(ordBuyerTerms);

    string funds_commit_raw_tx = builderMarket.FundsCommitRawTransaction();
    string ord_commit_raw_tx = builderMarket.OrdCommitRawTransaction();

    CMutableTransaction ord_commit_tx, funds_commit_tx;
    REQUIRE(DecodeHexTx(ord_commit_tx, ord_commit_raw_tx));
    REQUIRE(DecodeHexTx(funds_commit_tx, funds_commit_raw_tx));

    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(funds_commit_tx)));
    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_commit_tx)));

    w->btc().GenerateToAddress(w->btc().GetNewAddress(), "1");

    REQUIRE_NOTHROW(builderMarket.MarketSignOrdPayoffTx(hex(swap_script_key_M.GetLocalPrivKey())));
    string ordMarketTerms = builderMarket.Serialize(SwapInscriptionBuilder::MarketPayoffSig);


    // BUYER sign swap
    //--------------------------------------------------------------------------

    builderOrdBuyer.Deserialize(ordMarketTerms);
    REQUIRE_NOTHROW(builderOrdBuyer.SignFundsSwap(hex(swap_script_key_B.GetLocalPrivKey())));

    string ordFundsSignature = builderOrdBuyer.Serialize(SwapInscriptionBuilder::FundsSwapSig);


    // MARKET sign swap
    //--------------------------------------------------------------------------

    builderMarket.Deserialize(ordFundsSignature);
    REQUIRE_NOTHROW(builderMarket.MarketSignSwap(hex(swap_script_key_M.GetLocalPrivKey())));

    string ord_swap_raw_tx = builderMarket.OrdSwapRawTransaction();
    string ord_transfer_raw_tx = builderMarket.OrdPayoffRawTransaction();

    CMutableTransaction ord_swap_tx, ord_transfer_tx;
    REQUIRE(DecodeHexTx(ord_swap_tx, ord_swap_raw_tx));
    REQUIRE(DecodeHexTx(ord_transfer_tx, ord_transfer_raw_tx));

    PrecomputedTransactionData txdata;
    txdata.Init(ord_swap_tx, {ord_commit_tx.vout[0], funds_commit_tx.vout[0]}, /* force=*/ true);

    const CTxIn& ordTxin = ord_swap_tx.vin.at(0);
    MutableTransactionSignatureChecker TxOrdChecker(&ord_swap_tx, 0, ord_commit_tx.vout[0].nValue, txdata, MissingDataBehavior::FAIL);
    bool ordPath = VerifyScript(ordTxin.scriptSig, ord_commit_tx.vout[0].scriptPubKey, &ordTxin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TxOrdChecker);
    REQUIRE(ordPath);

    const CTxIn& txin = ord_swap_tx.vin.at(1);
    MutableTransactionSignatureChecker tx_checker(&ord_swap_tx, 1, funds_commit_tx.vout[0].nValue, txdata, MissingDataBehavior::FAIL);
    bool fundsPath = VerifyScript(txin.scriptSig, funds_commit_tx.vout[0].scriptPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, tx_checker);
    REQUIRE(fundsPath);

    CAmount fee_rate_amount = ParseAmount(fee_rate);
    CAmount ord_fee_rate_amount = ParseAmount(ord_fee_rate);

    REQUIRE(l15::CalculateTxFee(fee_rate_amount, funds_commit_tx) == l15::CalculateTxFee(fee_rate_amount, builderMarket.CreateFundsCommitTxTemplate()));
    REQUIRE(l15::CalculateTxFee(ord_fee_rate_amount, ord_commit_tx) == l15::CalculateTxFee(ord_fee_rate_amount, builderMarket.CreateOrdCommitTxTemplate()));
    REQUIRE(l15::CalculateTxFee(fee_rate_amount, ord_swap_tx) == l15::CalculateTxFee(fee_rate_amount, builderMarket.CreateSwapTxTemplate(true)));
    REQUIRE(l15::CalculateTxFee(fee_rate_amount, ord_transfer_tx) == l15::CalculateTxFee(fee_rate_amount, builderMarket.CreatePayoffTxTemplate()));

    CAmount realFee = l15::CalculateTxFee(fee_rate_amount, funds_commit_tx) +
                      l15::CalculateTxFee(ord_fee_rate_amount, ord_commit_tx) +
                      l15::CalculateTxFee(fee_rate_amount, ord_swap_tx) +
                      l15::CalculateTxFee(fee_rate_amount, ord_transfer_tx);

    REQUIRE(realFee == builderMarket.getWholeFee());
}
