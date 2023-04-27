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

const std::string DEFAULT_FEE_RATE = "0.00011";
const std::string DEFAULT_ORD_MINING_FEE_RATE = "0.000022";
const std::string ORD_PRICE = "0.0001";
const std::string MARKET_FEE = "0.00001";
const std::string DEFAULT_ORD_AMOUNT = "0.0001";

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

    SwapInscriptionBuilder builderOrdBuyer(ORD_PRICE, MARKET_FEE);
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

    CAmount change = 150;
    CAmount minFunding = ParseAmount(builderOrdBuyer.GetMinFundingAmount());

    const std::string fund_with_change = FormatAmount(minFunding + 3000);
    const std::string fund_without_change = FormatAmount(minFunding + change * 4);
    const std::string fund_lack = FormatAmount(minFunding - 1);

    auto funds_amount = GENERATE_REF(fund_with_change, fund_without_change, fund_lack);

    //Create funds utxo
    string funds_addr = w->bech32().Encode(funds_utxo_key.GetLocalPubKey());
    string funds_txid = w->btc().SendToAddress(funds_addr, funds_amount);
    auto funds_prevout = w->btc().CheckOutput(funds_txid, funds_addr);

    builderOrdBuyer.FundsUTXO(get<0>(funds_prevout).hash.GetHex(), get<0>(funds_prevout).n, funds_amount);
    builderOrdBuyer.SwapScriptPubKeyB(hex(swap_script_key_B.GetLocalPubKey()));
    //REQUIRE_NOTHROW(builderOrdBuyer.SignFundsCommitment(hex(funds_utxo_key.GetLocalPrivKey())));

    if (funds_amount == fund_lack) {
        REQUIRE_THROWS_AS(builderOrdBuyer.SignFundsCommitment(hex(funds_utxo_key.GetLocalPrivKey())), l15::TransactionError);
    } else {
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

        REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_swap_tx)));
        REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(ord_transfer_tx)));

        w->btc().GenerateToAddress(w->btc().GetNewAddress(), "1");

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

                REQUIRE(l15::CalculateTxFee(fee_rate_amount, funds_commit_tx) ==
                        l15::CalculateTxFee(fee_rate_amount, builderMarket.CreateFundsCommitTxTemplate()));
                REQUIRE(l15::CalculateTxFee(fee_rate_amount, ord_swap_tx) ==
                        l15::CalculateTxFee(fee_rate_amount, builderMarket.CreateSwapTxTemplate(true)));
                REQUIRE(l15::CalculateTxFee(fee_rate_amount, ord_transfer_tx) ==
                        l15::CalculateTxFee(fee_rate_amount, builderMarket.CreatePayoffTxTemplate()));

                CAmount realFee = l15::CalculateTxFee(fee_rate_amount, funds_commit_tx) +
                                  l15::CalculateTxFee(fee_rate_amount, ord_swap_tx) +
                                  l15::CalculateTxFee(fee_rate_amount, ord_transfer_tx);

                REQUIRE(realFee == builderMarket.CalculateWholeFee());
            }
        } else {
            REQUIRE(funds_commit_tx.vout.size() == 1);
        }
    }
}
