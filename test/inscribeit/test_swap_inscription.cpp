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

#include "test_case_wrapper.hpp"

using namespace l15;
using namespace l15::core;
using namespace l15::inscribeit;

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

std::unique_ptr<TestcaseWrapper> w;

const std::string DEFAULT_FEE_RATE = "0.000011";
const std::string DEFAULT_ORD_MINING_FEE_RATE = "0.000022";
const std::string ORD_PRICE = "0.0001";
const std::string MARKET_FEE = "0.00001";
const std::string DEFAULT_ORD_AMOUNT = "0.00025";

int main(int argc, char* argv[])
{
    std::string configpath;
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

    w = std::make_unique<TestcaseWrapper>(configpath);

    return session.run();
}


TEST_CASE("FundsPayBack")
{
    ChannelKeys swap_script_key_B;
    ChannelKeys swap_script_key_M;
    seckey unspendable_factor = ChannelKeys::GetStrongRandomKey();

    //get key pair
    ChannelKeys funds_utxo_key;

    //Create ord utxo
    string funds_addr = w->bech32().Encode(funds_utxo_key.GetLocalPubKey());
    string funds_txid = w->btc().SendToAddress(funds_addr, "0.15");
    auto funds_prevout = w->btc().CheckOutput(funds_txid, funds_addr);

    std::string fee_rate;
    try {
        fee_rate = w->btc().EstimateSmartFee("1");
    }
    catch(...) {
        fee_rate = "0.00011";
    }

    SwapInscriptionBuilder builderOrdBuyer("regtest", ORD_PRICE, MARKET_FEE);
    builderOrdBuyer.SetMiningFeeRate(fee_rate);
    builderOrdBuyer.SetSwapScriptPubKeyM(hex(swap_script_key_M.GetLocalPubKey()));
    builderOrdBuyer.SwapScriptPubKeyB(hex(swap_script_key_B.GetLocalPubKey()));

    //Exchange Commit UTXO
    //---------------------

    builderOrdBuyer.FundsUTXO(get<0>(funds_prevout).hash.GetHex(), get<0>(funds_prevout).n, FormatAmount(get<1>(funds_prevout).nValue));
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

TEST_CASE("FullSwapWithSections")
{
    ChannelKeys swap_script_key_A;
    ChannelKeys swap_script_key_B;
    ChannelKeys swap_script_key_M;
    //get key pair
    ChannelKeys ord_utxo_key;
    ChannelKeys funds_utxo_key;

    std::string ord_mining_fee_rate = DEFAULT_ORD_MINING_FEE_RATE;
    std::string fee_rate;
    try {
        fee_rate = w->btc().EstimateSmartFee("1");
    }
    catch(...) {
        fee_rate = DEFAULT_FEE_RATE;
    }

    // ORD side terms
    //--------------------------------------------------------------------------

    SwapInscriptionBuilder builderMarket(ORD_PRICE, MARKET_FEE);
    builderMarket.SetOrdCommitMiningFeeRate(ord_mining_fee_rate);
    builderMarket.SetSwapScriptPubKeyM(hex(swap_script_key_M.GetLocalPubKey()));

    auto transactions = builderMarket.GetTransactions();
    CAmount change = builderMarket.GetMinChange();
    CAmount minFunding = ParseAmount(builderMarket.GetMinFundingAmount());

    const std::string fund_with_change = "1";
    const std::string fund_without_change = FormatAmount(minFunding + change * 5.1);
    const std::string fund_lack = FormatAmount(minFunding - 1);

    auto funds_amount = GENERATE_REF(fund_with_change, fund_without_change, fund_lack);

    string marketOrdConditions = builderMarket.Serialize(ORD_TERMS);

    SwapInscriptionBuilder builderOrdSeller(ORD_PRICE, MARKET_FEE);
    builderOrdSeller.Deserialize(marketOrdConditions);

    builderOrdSeller.CheckContractTerms(ORD_TERMS);

    //Create ord utxo
    string ord_addr = w->bech32().Encode(ord_utxo_key.GetLocalPubKey());
    string ord_txid = w->btc().SendToAddress(ord_addr, DEFAULT_ORD_AMOUNT);
    auto ord_prevout = w->btc().CheckOutput(ord_txid, ord_addr);

    builderOrdSeller.OrdUTXO(get<0>(ord_prevout).hash.GetHex(), get<0>(ord_prevout).n, FormatAmount(get<1>(ord_prevout).nValue));
    builderOrdSeller.SwapScriptPubKeyA(hex(swap_script_key_A.GetLocalPubKey()));

    REQUIRE_NOTHROW(builderOrdSeller.SignOrdSwap(hex(ord_utxo_key.GetLocalPrivKey())));

    string ordSellerTerms = builderOrdSeller.Serialize(ORD_SWAP_SIG);


    // FUNDS side terms
    //--------------------------------------------------------------------------

    builderMarket.SetMiningFeeRate(fee_rate);
    string marketFundsConditions = builderMarket.Serialize(FUNDS_TERMS);

    SwapInscriptionBuilder builderOrdBuyer(ORD_PRICE, MARKET_FEE);
    builderOrdBuyer.Deserialize(marketFundsConditions);

    //Create funds utxo
    string funds_addr = w->bech32().Encode(funds_utxo_key.GetLocalPubKey());
    string funds_txid = w->btc().SendToAddress(funds_addr, funds_amount);
    auto funds_prevout = w->btc().CheckOutput(funds_txid, funds_addr);

    builderOrdBuyer.FundsUTXO(get<0>(funds_prevout).hash.GetHex(), get<0>(funds_prevout).n, funds_amount);
    builderOrdBuyer.SwapScriptPubKeyB(hex(swap_script_key_B.GetLocalPubKey()));
    REQUIRE_NOTHROW(builderOrdBuyer.SignFundsCommitment(hex(funds_utxo_key.GetLocalPrivKey())));

    string ordBuyerTerms = builderOrdBuyer.Serialize(FUNDS_COMMIT_SIG);
    if (funds_amount == fund_lack) {
        REQUIRE_THROWS_AS(builderOrdBuyer.SignFundsCommitment(hex(funds_utxo_key.GetLocalPrivKey())), l15::TransactionError);
    } else
        if (funds_amount != fund_lack) {
        REQUIRE_NOTHROW(builderOrdBuyer.SignFundsCommitment(hex(funds_utxo_key.GetLocalPrivKey())));

        string ordBuyerTerms = builderOrdBuyer.Serialize(SwapInscriptionBuilder::FundsCommitSig);

        // MARKET confirm terms
        //--------------------------------------------------------------------------

    builderMarket.Deserialize(ordSellerTerms);
    REQUIRE_NOTHROW(builderMarket.CheckContractTerms(ORD_SWAP_SIG));

    builderMarket.Deserialize(ordBuyerTerms);
    REQUIRE_NOTHROW(builderMarket.CheckContractTerms(FUNDS_COMMIT_SIG));

    string funds_commit_raw_tx = builderMarket.FundsCommitRawTransaction();

    CMutableTransaction /*ord_commit_tx,*/ funds_commit_tx;
    REQUIRE(DecodeHexTx(funds_commit_tx, funds_commit_raw_tx));

    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(funds_commit_tx)));

        w->btc().GenerateToAddress(w->btc().GetNewAddress(), "1");

    REQUIRE_NOTHROW(builderMarket.MarketSignOrdPayoffTx(hex(swap_script_key_M.GetLocalPrivKey())));
    string ordMarketTerms = builderMarket.Serialize(MARKET_PAYOFF_SIG);

        // BUYER sign swap
        //--------------------------------------------------------------------------

        builderOrdBuyer.Deserialize(ordMarketTerms);
        REQUIRE_NOTHROW(builderOrdBuyer.CheckContractTerms(SwapInscriptionBuilder::MarketPayoffSig));

    builderOrdBuyer.Deserialize(ordMarketTerms);
    REQUIRE_NOTHROW(builderOrdBuyer.CheckContractTerms(MARKET_PAYOFF_SIG));

        string ordFundsSignature = builderOrdBuyer.Serialize(SwapInscriptionBuilder::FundsSwapSig);

    string ordFundsSignature = builderOrdBuyer.Serialize(FUNDS_SWAP_SIG);

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

//    PrecomputedTransactionData txdata;
//    txdata.Init(ord_swap_tx, {ord_commit_tx.vout[0], funds_commit_tx.vout[0]}, /* force=*/ true);
//
//    const CTxIn& ordTxin = ord_swap_tx.vin.at(0);
//    MutableTransactionSignatureChecker TxOrdChecker(&ord_swap_tx, 0, ord_commit_tx.vout[0].nValue, txdata, MissingDataBehavior::FAIL);
//    bool ordPath = VerifyScript(ordTxin.scriptSig, ord_commit_tx.vout[0].scriptPubKey, &ordTxin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TxOrdChecker);
//    REQUIRE(ordPath);
//
//    const CTxIn& txin = ord_swap_tx.vin.at(1);
//    MutableTransactionSignatureChecker tx_checker(&ord_swap_tx, 1, funds_commit_tx.vout[0].nValue, txdata, MissingDataBehavior::FAIL);
//    bool fundsPath = VerifyScript(txin.scriptSig, funds_commit_tx.vout[0].scriptPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, tx_checker);
//    REQUIRE(fundsPath);

    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_swap_tx)));
    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_transfer_tx)));

        SECTION("BUYER_SPENDS_ORD") {
            xonly_pubkey payoff_pk = w->bech32().Decode(w->btc().GetNewAddress());
            CScript buyer_pubkeyscript = CScript() << 1 << payoff_pk;

            CMutableTransaction ord_payoff_tx;
            ord_payoff_tx.vin = {CTxIn(ord_transfer_tx.GetHash(), 0)};
            ord_payoff_tx.vin.front().scriptWitness.stack.emplace_back(64);
            ord_payoff_tx.vout = {CTxOut(ord_transfer_tx.vout[0].nValue, buyer_pubkeyscript)};
            ord_payoff_tx.vout.front().nValue = CalculateOutputAmount(ord_transfer_tx.vout[0].nValue,
                                                                      ParseAmount(fee_rate),
                                                                      ord_payoff_tx);

            REQUIRE_NOTHROW(
                    ord_payoff_tx.vin.front().scriptWitness.stack[0] = swap_script_key_B.SignTaprootTx(ord_payoff_tx, 0,
                                                                                                       {ord_transfer_tx.vout[0]},
                                                                                                       {}));

            REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_payoff_tx)));

            w->btc().GenerateToAddress(w->btc().GetNewAddress(), "1");
        }

        if (funds_amount == fund_with_change) {
            xonly_pubkey change_pk = w->bech32().Decode(w->btc().GetNewAddress());
            CScript buyer_change_pubkey_script = CScript() << 1 << change_pk;
            CMutableTransaction ord_change_spend_tx;
            ord_change_spend_tx.vin = {CTxIn(funds_commit_tx.GetHash(), 1)};
            ord_change_spend_tx.vin.front().scriptWitness.stack.emplace_back(64);
            ord_change_spend_tx.vout = {CTxOut(funds_commit_tx.vout[1].nValue, buyer_change_pubkey_script)};
            ord_change_spend_tx.vout.front().nValue = CalculateOutputAmount(funds_commit_tx.vout[1].nValue,
                                                                            ParseAmount(fee_rate), ord_change_spend_tx);

            SECTION("MARKET_SPENDS_CHANGE_OUTPUT") {
                REQUIRE_NOTHROW(
                        ord_change_spend_tx.vin.front().scriptWitness.stack[0] = swap_script_key_M.SignTaprootTx(
                                ord_change_spend_tx, 0, {funds_commit_tx.vout[1]}, {}));

                REQUIRE_THROWS(w->btc().SpendTx(CTransaction(ord_change_spend_tx)));
            }

            SECTION("BUYER_SPENDS_CHANGE_OUTPUT") {
                REQUIRE_NOTHROW(
                        ord_change_spend_tx.vin.front().scriptWitness.stack[0] = swap_script_key_B.SignTaprootTx(
                                ord_change_spend_tx, 0, {funds_commit_tx.vout[1]}, {}));

                REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_change_spend_tx)));

                w->btc().GenerateToAddress(w->btc().GetNewAddress(), "1");
                REQUIRE(funds_commit_tx.vout.size() == 2);
            }

            SECTION("FEE_ESTIMATION") {
                CAmount fee_rate_amount = ParseAmount(fee_rate);
                CAmount ord_fee_rate_amount = ParseAmount(ord_mining_fee_rate);

                REQUIRE(l15::CalculateTxFee(fee_rate_amount, funds_commit_tx) ==
                        l15::CalculateTxFee(fee_rate_amount, builderMarket.CreateFundsCommitTxTemplate()));
                REQUIRE(l15::CalculateTxFee(ord_fee_rate_amount, ord_commit_tx) ==
                        l15::CalculateTxFee(ord_fee_rate_amount, builderMarket.CreateOrdCommitTxTemplate()));
                REQUIRE(l15::CalculateTxFee(fee_rate_amount, ord_swap_tx) ==
                        l15::CalculateTxFee(fee_rate_amount, builderMarket.CreateSwapTxTemplate(true)));
                REQUIRE(l15::CalculateTxFee(fee_rate_amount, ord_transfer_tx) ==
                        l15::CalculateTxFee(fee_rate_amount, builderMarket.CreatePayoffTxTemplate()));

                CAmount realFee = l15::CalculateTxFee(fee_rate_amount, funds_commit_tx) +
                                  l15::CalculateTxFee(ord_fee_rate_amount, ord_commit_tx) +
                                  l15::CalculateTxFee(fee_rate_amount, ord_swap_tx) +
                                  l15::CalculateTxFee(fee_rate_amount, ord_transfer_tx);

                REQUIRE(realFee == builderMarket.CalculateWholeFee());
            }
        } else
        if (funds_amount == fund_without_change) {
            REQUIRE(funds_commit_tx.vout.size() == 1);
        }
    }
}
/*
TEST_CASE("FundsNotEnough")
{
    ChannelKeys swap_script_key_A;
    ChannelKeys swap_script_key_B;
    ChannelKeys swap_script_key_M;
    seckey preimage = ChannelKeys::GetStrongRandomKey();
    bytevector swap_hash(32);
    CHash256().Write(preimage).Finalize(swap_hash);
    //get key pair
    ChannelKeys ord_utxo_key;
    ChannelKeys funds_utxo_key;

    std::string fee_rate;
    try {
        fee_rate = w->btc().EstimateSmartFee("1");
    }
    catch(...) {
        fee_rate = DEFAULT_FEE_RATE;
    }
    std::clog << "Fee rate: " << fee_rate << std::endl;

    // ORD side terms
    //--------------------------------------------------------------------------

    SwapInscriptionBuilder builderMarket(ORD_PRICE, MARKET_FEE);
    builderMarket.SetMiningFeeRate(fee_rate);
    builderMarket.SetSwapScriptPubKeyM(hex(swap_script_key_M.GetLocalPubKey()));


    string marketOrdConditions = builderMarket.Serialize(ORD_TERMS);

    SwapInscriptionBuilder builderOrdSeller(ORD_PRICE, MARKET_FEE);
    builderOrdSeller.Deserialize(marketOrdConditions);

    builderOrdSeller.CheckContractTerms(ORD_TERMS);

    //Create ord utxo
    string ord_addr = w->bech32().Encode(ord_utxo_key.GetLocalPubKey());
    string ord_txid = w->btc().SendToAddress(ord_addr, "0.0001");
    auto ord_prevout = w->btc().CheckOutput(ord_txid, ord_addr);

    builderOrdSeller.SwapScriptPubKeyA(hex(swap_script_key_A.GetLocalPubKey()));
    builderOrdSeller.OrdUTXO(get<0>(ord_prevout).hash.GetHex(), get<0>(ord_prevout).n, "0.0001");

    REQUIRE_NOTHROW(builderOrdSeller.SignOrdSwap(hex(swap_script_key_A.GetLocalPrivKey())));

    string ordSellerTerms = builderOrdSeller.Serialize(ORD_SWAP_SIG);


    // FUNDS side terms
    //--------------------------------------------------------------------------

    //builderMarket.SetMiningFeeRate(fee_rate);
    string marketFundsConditions = builderMarket.Serialize(FUNDS_TERMS);

    SwapInscriptionBuilder builderOrdBuyer(ORD_PRICE, MARKET_FEE);
    builderOrdBuyer.Deserialize(marketFundsConditions);

    //Create insufficient funds utxo
    std::string funds_amount = FormatAmount(ParseAmount(builderOrdBuyer.GetMinFundingAmount()) - 1);
    std::string funds_addr = w->bech32().Encode(funds_utxo_key.GetLocalPubKey());
    std::string funds_txid = w->btc().SendToAddress(funds_addr, funds_amount);

    auto funds_prevout = w->btc().CheckOutput(funds_txid, funds_addr);

    builderOrdBuyer.SwapScriptPubKeyB(hex(swap_script_key_B.GetLocalPubKey()));
    builderOrdBuyer.FundsUTXO(get<0>(funds_prevout).hash.GetHex(), get<0>(funds_prevout).n, funds_amount);
    REQUIRE_THROWS_AS(builderOrdBuyer.SignFundsCommitment(hex(funds_utxo_key.GetLocalPrivKey())), l15::TransactionError);

    //Create funds utxo
    funds_amount = builderOrdBuyer.GetMinFundingAmount();

    builderOrdBuyer.FundsUTXO(get<0>(funds_prevout).hash.GetHex(), get<0>(funds_prevout).n, funds_amount);
    REQUIRE_NOTHROW(builderOrdBuyer.SignFundsCommitment(hex(funds_utxo_key.GetLocalPrivKey())));
}

TEST_CASE("FullSwapFee")
{
    const std::string ORD_PRICE = "0.0001";
    const std::string MARKET_FEE = "0.00001";
    const std::string FUNDS_AMOUNT = "0.0002";

    ChannelKeys swap_script_key_A;
    ChannelKeys swap_script_key_B;
    ChannelKeys swap_script_key_M;
    //get key pair
    ChannelKeys ord_utxo_key;
    ChannelKeys funds_utxo_key;

    std::string fee_rate;
    try {
        fee_rate = w->btc().EstimateSmartFee("1");
    }
    catch(...) {
        fee_rate = "0.00011";
    }
    //std::clog << "Fee rate: " << fee_rate << std::endl;


    // ORD side terms
    //--------------------------------------------------------------------------

    SwapInscriptionBuilder builderMarket(ORD_PRICE, MARKET_FEE);
    builderMarket.SetSwapScriptPubKeyM(hex(swap_script_key_M.GetLocalPubKey()));

    string marketOrdConditions = builderMarket.Serialize(ORD_TERMS);

    SwapInscriptionBuilder builderOrdSeller(ORD_PRICE, MARKET_FEE);
    builderOrdSeller.Deserialize(marketOrdConditions);

    builderOrdSeller.CheckContractTerms(ORD_TERMS);

    //Create ord utxo
    string ord_addr = w->bech32().Encode(ord_utxo_key.GetLocalPubKey());
    string ord_txid = w->btc().SendToAddress(ord_addr, "0.0001");
    auto ord_prevout = w->btc().CheckOutput(ord_txid, ord_addr);

    builderOrdSeller.SwapScriptPubKeyA(hex(swap_script_key_A.GetLocalPubKey()));
    builderOrdSeller.OrdUTXO(get<0>(ord_prevout).hash.GetHex(), get<0>(ord_prevout).n, "0.0001");

    REQUIRE_NOTHROW(builderOrdSeller.SignOrdSwap(hex(ord_utxo_key.GetLocalPrivKey())));

    string ordSellerTerms = builderOrdSeller.Serialize(ORD_SWAP_SIG);


    // FUNDS side terms
    //--------------------------------------------------------------------------

    builderMarket.SetMiningFeeRate(fee_rate);
    string marketFundsConditions = builderMarket.Serialize(FUNDS_TERMS);

    SwapInscriptionBuilder builderOrdBuyer(ORD_PRICE, MARKET_FEE);
    builderOrdBuyer.Deserialize(marketFundsConditions);

    //Create funds utxo
    string funds_addr = w->bech32().Encode(funds_utxo_key.GetLocalPubKey());
    string funds_txid = w->btc().SendToAddress(funds_addr, FUNDS_AMOUNT);
    auto funds_prevout = w->btc().CheckOutput(funds_txid, funds_addr);

    builderOrdBuyer.SwapScriptPubKeyB(hex(swap_script_key_B.GetLocalPubKey()));
    builderOrdBuyer.FundsUTXO(get<0>(funds_prevout).hash.GetHex(), get<0>(funds_prevout).n, FUNDS_AMOUNT);
    REQUIRE_NOTHROW(builderOrdBuyer.SignFundsCommitment(hex(funds_utxo_key.GetLocalPrivKey())));

    string ordBuyerTerms = builderOrdBuyer.Serialize(FUNDS_COMMIT_SIG);


    // MARKET confirm terms
    //--------------------------------------------------------------------------

    builderMarket.Deserialize(ordSellerTerms);
    builderMarket.Deserialize(ordBuyerTerms);

    string funds_commit_raw_tx = builderMarket.FundsCommitRawTransaction();

    CMutableTransaction funds_commit_tx;
    REQUIRE(DecodeHexTx(funds_commit_tx, funds_commit_raw_tx));

    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(funds_commit_tx)));

    w->btc().GenerateToAddress(w->btc().GetNewAddress(), "1");

    REQUIRE_NOTHROW(builderMarket.MarketSignOrdPayoffTx(hex(swap_script_key_M.GetLocalPrivKey())));
    string ordMarketTerms = builderMarket.Serialize(MARKET_PAYOFF_SIG);


    // BUYER sign swap
    //--------------------------------------------------------------------------

    builderOrdBuyer.Deserialize(ordMarketTerms);
    REQUIRE_NOTHROW(builderOrdBuyer.SignFundsSwap(hex(swap_script_key_B.GetLocalPrivKey())));

    string ordFundsSignature = builderOrdBuyer.Serialize(FUNDS_SWAP_SIG);


    // MARKET sign swap
    //--------------------------------------------------------------------------

    builderMarket.Deserialize(ordFundsSignature);
    REQUIRE_NOTHROW(builderMarket.MarketSignSwap(hex(swap_script_key_M.GetLocalPrivKey())));

    string ord_swap_raw_tx = builderMarket.OrdSwapRawTransaction();
    string ord_transfer_raw_tx = builderMarket.OrdPayoffRawTransaction();

    CMutableTransaction ord_swap_tx, ord_transfer_tx;
    REQUIRE(DecodeHexTx(ord_swap_tx, ord_swap_raw_tx));
    REQUIRE(DecodeHexTx(ord_transfer_tx, ord_transfer_raw_tx));

    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_swap_tx)));
    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_transfer_tx)));

    w->btc().GenerateToAddress(w->btc().GetNewAddress(), "1");


    // BUYER spends his ord
    //--------------------------------------------------------------------------

    xonly_pubkey payoff_pk = w->bech32().Decode(w->btc().GetNewAddress());
    CScript buyer_pubkeyscript = CScript() << 1 << payoff_pk;


    CMutableTransaction ord_payoff_tx;
    ord_payoff_tx.vin = {CTxIn(ord_transfer_tx.GetHash(), 0)};
    ord_payoff_tx.vin.front().scriptWitness.stack.emplace_back(64);
    ord_payoff_tx.vout = {CTxOut(ord_transfer_tx.vout[0].nValue, buyer_pubkeyscript)};
    ord_payoff_tx.vout.front().nValue = CalculateOutputAmount(ord_transfer_tx.vout[0].nValue, ParseAmount(fee_rate), ord_payoff_tx);

    REQUIRE_NOTHROW(ord_payoff_tx.vin.front().scriptWitness.stack[0] = swap_script_key_B.SignTaprootTx(ord_payoff_tx, 0, {ord_transfer_tx.vout[0]}, {}));

    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_payoff_tx)));

    w->btc().GenerateToAddress(w->btc().GetNewAddress(), "1");

    REQUIRE(funds_commit_tx.vout.size() == 2);


    // BUYER spends his change
    //--------------------------------------------------------------------------

    CMutableTransaction change_tx;
    change_tx.vin = {CTxIn(funds_commit_tx.GetHash(), 1)};
    change_tx.vin.front().scriptWitness.stack.emplace_back(64);
    change_tx.vout = {CTxOut(0, buyer_pubkeyscript)};
    change_tx.vout.front().nValue = CalculateOutputAmount(funds_commit_tx.vout[1].nValue, ParseAmount(fee_rate), change_tx);

    REQUIRE_NOTHROW(change_tx.vin.front().scriptWitness.stack[0] = swap_script_key_B.SignTaprootTx(change_tx, 0, {funds_commit_tx.vout[1]}, {}));

    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(change_tx)));
}

TEST_CASE("FullSwapMinChange")
{
    const std::string ORD_PRICE = "0.0001";
    const std::string MARKET_FEE = "0.00001";

    ChannelKeys swap_script_key_A;
    ChannelKeys swap_script_key_B;
    ChannelKeys swap_script_key_M;
    //get key pair
    ChannelKeys ord_utxo_key;
    ChannelKeys funds_utxo_key;

    std::string fee_rate;
    try {
        fee_rate = w->btc().EstimateSmartFee("1");
    }
    catch(...) {
        fee_rate = "0.00011";
    }
    //std::clog << "Fee rate: " << fee_rate << std::endl;


    // ORD side terms
    //--------------------------------------------------------------------------

    SwapInscriptionBuilder builderMarket(ORD_PRICE, MARKET_FEE);
    builderMarket.SetSwapScriptPubKeyM(hex(swap_script_key_M.GetLocalPubKey()));

    string marketOrdConditions = builderMarket.Serialize(ORD_TERMS);

    SwapInscriptionBuilder builderOrdSeller(ORD_PRICE, MARKET_FEE);
    builderOrdSeller.Deserialize(marketOrdConditions);

    builderOrdSeller.CheckContractTerms(ORD_TERMS);

    //Create ord utxo
    string ord_addr = w->bech32().Encode(ord_utxo_key.GetLocalPubKey());
    string ord_txid = w->btc().SendToAddress(ord_addr, "0.0001");
    auto ord_prevout = w->btc().CheckOutput(ord_txid, ord_addr);

    builderOrdSeller.SwapScriptPubKeyA(hex(swap_script_key_A.GetLocalPubKey()));
    builderOrdSeller.OrdUTXO(get<0>(ord_prevout).hash.GetHex(), get<0>(ord_prevout).n, "0.0001");

    REQUIRE_NOTHROW(builderOrdSeller.SignOrdSwap(hex(ord_utxo_key.GetLocalPrivKey())));

    string ordSellerTerms = builderOrdSeller.Serialize(ORD_SWAP_SIG);


    // FUNDS side terms
    //--------------------------------------------------------------------------

    builderMarket.SetMiningFeeRate(fee_rate);
    string marketFundsConditions = builderMarket.Serialize(FUNDS_TERMS);

    SwapInscriptionBuilder builderOrdBuyer(ORD_PRICE, MARKET_FEE);
    builderOrdBuyer.Deserialize(marketFundsConditions);

    CAmount dust = Dust(ParseAmount(fee_rate));

    std::clog << "Dust amount: " << dust << std::endl;

    const std::string funds_amount = FormatAmount(ParseAmount(builderOrdBuyer.GetMinFundingAmount()) + dust + 1);

    //Create funds utxo
    string funds_addr = w->bech32().Encode(funds_utxo_key.GetLocalPubKey());
    string funds_txid = w->btc().SendToAddress(funds_addr, funds_amount);
    auto funds_prevout = w->btc().CheckOutput(funds_txid, funds_addr);

    builderOrdBuyer.SwapScriptPubKeyB(hex(swap_script_key_B.GetLocalPubKey()));
    builderOrdBuyer.FundsUTXO(get<0>(funds_prevout).hash.GetHex(), get<0>(funds_prevout).n, funds_amount);
    REQUIRE_NOTHROW(builderOrdBuyer.SignFundsCommitment(hex(funds_utxo_key.GetLocalPrivKey())));

    string ordBuyerTerms = builderOrdBuyer.Serialize(FUNDS_COMMIT_SIG);


    // MARKET confirm terms
    //--------------------------------------------------------------------------

    builderMarket.Deserialize(ordSellerTerms);
    builderMarket.Deserialize(ordBuyerTerms);

    string funds_commit_raw_tx = builderMarket.FundsCommitRawTransaction();

    CMutableTransaction funds_commit_tx;
    REQUIRE(DecodeHexTx(funds_commit_tx, funds_commit_raw_tx));

    REQUIRE(funds_commit_tx.vout.size() == 2);
    REQUIRE(funds_commit_tx.vout[1].nValue == dust + 1);

    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(funds_commit_tx)));

    w->btc().GenerateToAddress(w->btc().GetNewAddress(), "1");

    REQUIRE_NOTHROW(builderMarket.MarketSignOrdPayoffTx(hex(swap_script_key_M.GetLocalPrivKey())));
    string ordMarketTerms = builderMarket.Serialize(MARKET_PAYOFF_SIG);


    // BUYER sign swap
    //--------------------------------------------------------------------------

    builderOrdBuyer.Deserialize(ordMarketTerms);
    REQUIRE_NOTHROW(builderOrdBuyer.SignFundsSwap(hex(swap_script_key_B.GetLocalPrivKey())));

    string ordFundsSignature = builderOrdBuyer.Serialize(FUNDS_SWAP_SIG);


    // MARKET sign swap
    //--------------------------------------------------------------------------

    builderMarket.Deserialize(ordFundsSignature);
    REQUIRE_NOTHROW(builderMarket.MarketSignSwap(hex(swap_script_key_M.GetLocalPrivKey())));

    string ord_swap_raw_tx = builderMarket.OrdSwapRawTransaction();
    string ord_transfer_raw_tx = builderMarket.OrdPayoffRawTransaction();

    CMutableTransaction ord_swap_tx, ord_transfer_tx;
    REQUIRE(DecodeHexTx(ord_swap_tx, ord_swap_raw_tx));
    REQUIRE(DecodeHexTx(ord_transfer_tx, ord_transfer_raw_tx));

    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_swap_tx)));
    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_transfer_tx)));

    w->btc().GenerateToAddress(w->btc().GetNewAddress(), "1");


    // BUYER spends his ord
    //--------------------------------------------------------------------------

    xonly_pubkey payoff_pk = w->bech32().Decode(w->btc().GetNewAddress());
    CScript buyer_pubkeyscript = CScript() << 1 << payoff_pk;


    CMutableTransaction ord_payoff_tx;
    ord_payoff_tx.vin = {CTxIn(ord_transfer_tx.GetHash(), 0)};
    ord_payoff_tx.vin.front().scriptWitness.stack.emplace_back(64);
    ord_payoff_tx.vout = {CTxOut(ord_transfer_tx.vout[0].nValue, buyer_pubkeyscript)};
    ord_payoff_tx.vout.front().nValue = CalculateOutputAmount(ord_transfer_tx.vout[0].nValue, ParseAmount(fee_rate), ord_payoff_tx);

    REQUIRE_NOTHROW(ord_payoff_tx.vin.front().scriptWitness.stack[0] = swap_script_key_B.SignTaprootTx(ord_payoff_tx, 0, {ord_transfer_tx.vout[0]}, {}));

    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_payoff_tx)));

    w->btc().GenerateToAddress(w->btc().GetNewAddress(), "1");

    REQUIRE(funds_commit_tx.vout.size() == 2);
}


TEST_CASE("SwapWithNoChange")
{
    ChannelKeys swap_script_key_A;
    ChannelKeys swap_script_key_B;
    ChannelKeys swap_script_key_M;
    //get key pair
    ChannelKeys ord_utxo_key;
    ChannelKeys funds_utxo_key;

    std::string fee_rate;
    try {
        fee_rate = w->btc().EstimateSmartFee("1");
    }
    catch(...) {
        fee_rate = DEFAULT_FEE_RATE;
    }

    // ORD side terms
    //--------------------------------------------------------------------------

    SwapInscriptionBuilder builderMarket(ORD_PRICE, MARKET_FEE);
    builderMarket.SetSwapScriptPubKeyM(hex(swap_script_key_M.GetLocalPubKey()));

    string marketOrdConditions = builderMarket.Serialize(ORD_TERMS);

    SwapInscriptionBuilder builderOrdSeller(ORD_PRICE, MARKET_FEE);
    builderOrdSeller.Deserialize(marketOrdConditions);

    builderOrdSeller.CheckContractTerms(ORD_TERMS);

    //Create ord utxo
    string ord_addr = w->bech32().Encode(ord_utxo_key.GetLocalPubKey());
    string ord_txid = w->btc().SendToAddress(ord_addr, "0.0001");
    auto ord_prevout = w->btc().CheckOutput(ord_txid, ord_addr);

    builderOrdSeller.OrdUTXO(get<0>(ord_prevout).hash.GetHex(), get<0>(ord_prevout).n, FormatAmount(get<1>(ord_prevout).nValue));
    builderOrdSeller.SwapScriptPubKeyA(hex(swap_script_key_A.GetLocalPubKey()));

    REQUIRE_NOTHROW(builderOrdSeller.SignOrdSwap(hex(ord_utxo_key.GetLocalPrivKey())));

    string ordSellerTerms = builderOrdSeller.Serialize(ORD_SWAP_SIG);


    // FUNDS side terms
    //--------------------------------------------------------------------------

    builderMarket.MiningFeeRate(fee_rate);
    string marketFundsConditions = builderMarket.Serialize(FUNDS_TERMS);

    SwapInscriptionBuilder builderOrdBuyer(ORD_PRICE, MARKET_FEE);
    builderOrdBuyer.Deserialize(marketFundsConditions);

    const std::string funds_amount = FormatAmount(ParseAmount(builderOrdBuyer.GetMinFundingAmount()) + 50);

    //Create funds utxo
    string funds_addr = w->bech32().Encode(funds_utxo_key.GetLocalPubKey());
    string funds_txid = w->btc().SendToAddress(funds_addr, funds_amount);
    auto funds_prevout = w->btc().CheckOutput(funds_txid, funds_addr);

    builderOrdBuyer.FundsUTXO(get<0>(funds_prevout).hash.GetHex(), get<0>(funds_prevout).n, funds_amount)
                   .SwapScriptPubKeyB(hex(swap_script_key_B.GetLocalPubKey()));
    REQUIRE_NOTHROW(builderOrdBuyer.SignFundsCommitment(hex(funds_utxo_key.GetLocalPrivKey())));

    string ordBuyerTerms = builderOrdBuyer.Serialize(FUNDS_COMMIT_SIG);


    // MARKET confirm terms
    //--------------------------------------------------------------------------

    builderMarket.Deserialize(ordSellerTerms);
    REQUIRE_NOTHROW(builderMarket.CheckContractTerms(ORD_SWAP_SIG));

    builderMarket.Deserialize(ordBuyerTerms);
    REQUIRE_NOTHROW(builderMarket.CheckContractTerms(FUNDS_COMMIT_SIG));

    string funds_commit_raw_tx = builderMarket.FundsCommitRawTransaction();

    CMutableTransaction funds_commit_tx;
    REQUIRE(DecodeHexTx(funds_commit_tx, funds_commit_raw_tx));
    REQUIRE(funds_commit_tx.vout.size() == 1);
    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(funds_commit_tx)));

    w->btc().GenerateToAddress(w->btc().GetNewAddress(), "1");

    REQUIRE_NOTHROW(builderMarket.MarketSignOrdPayoffTx(hex(swap_script_key_M.GetLocalPrivKey())));
    string ordMarketTerms = builderMarket.Serialize(MARKET_PAYOFF_SIG);

    // BUYER sign swap
    //--------------------------------------------------------------------------

    builderOrdBuyer.Deserialize(ordMarketTerms);
    REQUIRE_NOTHROW(builderOrdBuyer.CheckContractTerms(MARKET_PAYOFF_SIG));

    REQUIRE_NOTHROW(builderOrdBuyer.SignFundsSwap(hex(swap_script_key_B.GetLocalPrivKey())));

    string ordFundsSignature = builderOrdBuyer.Serialize(FUNDS_SWAP_SIG);


    // MARKET sign swap
    //--------------------------------------------------------------------------

    builderMarket.Deserialize(ordFundsSignature);
    REQUIRE_NOTHROW(builderMarket.MarketSignSwap(hex(swap_script_key_M.GetLocalPrivKey())));

    string ord_swap_raw_tx = builderMarket.OrdSwapRawTransaction();
    string ord_transfer_raw_tx = builderMarket.OrdPayoffRawTransaction();

    CMutableTransaction ord_swap_tx, ord_transfer_tx;
    REQUIRE(DecodeHexTx(ord_swap_tx, ord_swap_raw_tx));
    REQUIRE(DecodeHexTx(ord_transfer_tx, ord_transfer_raw_tx));

//    PrecomputedTransactionData txdata;
//    txdata.Init(ord_swap_tx, {ord_commit_tx.vout[0], funds_commit_tx.vout[0]}, /* force=*/ true);
//
//    const CTxIn& ordTxin = ord_swap_tx.vin.at(0);
//    MutableTransactionSignatureChecker TxOrdChecker(&ord_swap_tx, 0, ord_commit_tx.vout[0].nValue, txdata, MissingDataBehavior::FAIL);
//    bool ordPath = VerifyScript(ordTxin.scriptSig, ord_commit_tx.vout[0].scriptPubKey, &ordTxin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TxOrdChecker);
//    REQUIRE(ordPath);
//
//    const CTxIn& txin = ord_swap_tx.vin.at(1);
//    MutableTransactionSignatureChecker tx_checker(&ord_swap_tx, 1, funds_commit_tx.vout[0].nValue, txdata, MissingDataBehavior::FAIL);
//    bool fundsPath = VerifyScript(txin.scriptSig, funds_commit_tx.vout[0].scriptPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, tx_checker);
//    REQUIRE(fundsPath);

    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_swap_tx)));
    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_transfer_tx)));

    w->btc().GenerateToAddress(w->btc().GetNewAddress(), "1");


    // BUYER spends his ord
    //--------------------------------------------------------------------------

    xonly_pubkey payoff_pk = w->bech32().Decode(w->btc().GetNewAddress());
    CScript buyer_pubkeyscript = CScript() << 1 << payoff_pk;


    CMutableTransaction ord_payoff_tx;
    ord_payoff_tx.vin = {CTxIn(ord_transfer_tx.GetHash(), 0)};
    ord_payoff_tx.vin.front().scriptWitness.stack.emplace_back(64);
    ord_payoff_tx.vout = {CTxOut(ord_transfer_tx.vout[0].nValue, buyer_pubkeyscript)};
    ord_payoff_tx.vout.front().nValue = CalculateOutputAmount(ord_transfer_tx.vout[0].nValue, ParseAmount(fee_rate), ord_payoff_tx);

    REQUIRE_NOTHROW(ord_payoff_tx.vin.front().scriptWitness.stack[0] = swap_script_key_B.SignTaprootTx(ord_payoff_tx, 0, {ord_transfer_tx.vout[0]}, {}));

    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_payoff_tx)));

    w->btc().GenerateToAddress(w->btc().GetNewAddress(), "1");

    REQUIRE(funds_commit_tx.vout.size() == 1);
}
*/

