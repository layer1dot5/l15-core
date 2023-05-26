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
#include "create_inscription.hpp"
#include "inscription.hpp"
#include "core_io.h"
#include "serialize.h"

#include "test_case_wrapper.hpp"

using namespace l15;
using namespace l15::core;
using namespace l15::inscribeit;

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;


std::unique_ptr<TestcaseWrapper> w;

std::string GenRandomString(const int len) {
    static const char alphanum[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
    std::string tmp_s;
    tmp_s.reserve(len);

    for (int i = 0; i < len; ++i) {
        tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    return tmp_s;
}

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

struct CreateCondition
{
    std::vector<CAmount> funds;
    InscribeType type;
    bool has_change;
    bool has_parent;
};

std::string collection_id;
seckey collection_script_sk;
xonly_pubkey collection_int_pk;
Transfer collection_utxo;

TEST_CASE("single inscribe")
{
    ChannelKeys utxo_key;
    ChannelKeys script_key, inscribe_key;
    ChannelKeys collection_script_key, collection_int_key;

    string addr = w->bech32().Encode(utxo_key.GetLocalPubKey());

    xonly_pubkey destination_pk = w->bech32().Decode(w->btc().GetNewAddress());

    std::string fee_rate;
    try {
        fee_rate = w->btc().EstimateSmartFee("1");
    }
    catch(...) {
        fee_rate = "0.00001";
    }

    std::clog << "Fee rate: " << fee_rate << std::endl;

    std::string content_type = "text/ascii";
    auto content = hex(GenRandomString(2048));

    CreateInscriptionBuilder test_inscription(INSCRIPTION, "0.00000546");
    REQUIRE_NOTHROW(test_inscription.MiningFeeRate(fee_rate).Data(content_type, content));
    std::string inscription_amount = test_inscription.GetMinFundingAmount("");

    CreateInscriptionBuilder test_collection(COLLECTION, "0.00000546");
    REQUIRE_NOTHROW(test_collection.MiningFeeRate(fee_rate).Data(content_type, content));
    std::string collection_amount = test_collection.GetMinFundingAmount("");

    CreateCondition inscription {{10000}, INSCRIPTION, true, false};
    CreateCondition collection {{10000}, COLLECTION, true, false};
    CreateCondition exact_inscription {{ParseAmount(inscription_amount)}, INSCRIPTION, false, false};
    CreateCondition exact_collection {{ParseAmount(collection_amount)}, COLLECTION, false, false};

    std::clog << "Inscription ord amount: " << inscription_amount << '\n';
    std::clog << "Collection root ord amount: " << collection_amount << std::endl;

    auto condition = GENERATE_REF(move(inscription), move(collection), move(exact_inscription), move(exact_collection));

    string funds_txid = w->btc().SendToAddress(addr, FormatAmount(condition.funds[0]));
    auto prevout = w->btc().CheckOutput(funds_txid, addr);

    CreateInscriptionBuilder builder(condition.type, "0.00000546");
    CHECK_NOTHROW(builder.MiningFeeRate(fee_rate)
                         .Data(content_type, content)
                         .InscribePubKey(hex((condition.type == INSCRIPTION) ? destination_pk : inscribe_key.GetLocalPubKey()))
                         .ChangePubKey(hex(destination_pk))
                         .AddUTXO(get<0>(prevout).hash.GetHex(), get<0>(prevout).n, FormatAmount(condition.funds[0]), hex(utxo_key.GetLocalPubKey())));

    if (condition.type == COLLECTION) {
        CHECK_NOTHROW(builder.CollectionCommitPubKeys(hex(collection_script_key.GetLocalPubKey()), hex(collection_int_key.GetLocalPubKey())));
    }

    CHECK_NOTHROW(builder.SignCommit(0, hex(utxo_key.GetLocalPrivKey()), hex(script_key.GetLocalPubKey())));
    CHECK_NOTHROW(builder.SignInscription(hex(script_key.GetLocalPrivKey())));
    if (condition.type == COLLECTION) {
        CHECK_NOTHROW(builder.SignCollectionRootCommit(hex(inscribe_key.GetLocalPrivKey())));
    }

    std::string contract = builder.Serialize();
    std::clog << contract << std::endl;

    CreateInscriptionBuilder builder2(condition.type, "0.00000546");
    builder2.Deserialize(contract);

    stringvector rawtxs;
    CHECK_NOTHROW(rawtxs = builder2.RawTransactions());

    CMutableTransaction commitTx, revealTx, collectionCommitTx;
    if (condition.type == INSCRIPTION) {
        REQUIRE(rawtxs.size() == 2);
        REQUIRE(DecodeHexTx(commitTx, rawtxs[0]));
        REQUIRE(DecodeHexTx(revealTx, rawtxs[1]));
        CHECK(revealTx.vout[0].nValue == 546);
    }
    else if (condition.type == COLLECTION) {
        REQUIRE(rawtxs.size() == 3);
        REQUIRE(DecodeHexTx(commitTx, rawtxs[0]));
        REQUIRE(DecodeHexTx(revealTx, rawtxs[1]));
        REQUIRE(DecodeHexTx(collectionCommitTx, rawtxs[2]));
        CHECK(collectionCommitTx.vout[0].nValue == 546);

        collection_script_sk = collection_script_key.GetLocalPrivKey();
        collection_int_pk = collection_int_key.GetLocalPubKey();

        collection_id = revealTx.GetHash().GetHex() + "i0";
        std::string collection_taproot_pk = Collection::GetCollectionTapRootPubKey(collection_id,
                                                                                   hex(collection_script_key.GetLocalPrivKey()),
                                                                                   hex(collection_int_key.GetLocalPrivKey()));

        collection_utxo = {collectionCommitTx.GetHash().GetHex(), 0, 546, unhex<xonly_pubkey>(collection_taproot_pk)};
    }
    else {
        FAIL();
    }

    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(commitTx)));
    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(revealTx)));

    if (condition.type == COLLECTION) {
        REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(collectionCommitTx)));
    }
}

TEST_CASE("collection child")
{
    ChannelKeys utxo_key;
    ChannelKeys script_key, inscribe_key;
    ChannelKeys collection_script_key(collection_script_sk);
    ChannelKeys new_collection_script_key, new_collection_int_key;

    string addr = w->bech32().Encode(utxo_key.GetLocalPubKey());

    xonly_pubkey destination_pk = w->bech32().Decode(w->btc().GetNewAddress());

    std::string fee_rate;
    try {
        fee_rate = w->btc().EstimateSmartFee("1");
    }
    catch(...) {
        fee_rate = "0.00001";
    }

    std::clog << "Fee rate: " << fee_rate << std::endl;

    std::string content_type = "text/ascii";
    auto content = hex(GenRandomString(2048));

    CreateInscriptionBuilder test_inscription(INSCRIPTION, "0.00000546");
    REQUIRE_NOTHROW(test_inscription.MiningFeeRate(fee_rate).Data(content_type, content));
    std::string inscription_amount = test_inscription.GetMinFundingAmount("");

    CreateInscriptionBuilder test_collection(COLLECTION, "0.00000546");
    REQUIRE_NOTHROW(test_collection.MiningFeeRate(fee_rate).Data(content_type, content));
    std::string collection_amount = test_collection.GetMinFundingAmount("");

    CreateCondition inscription {{10000}, INSCRIPTION, true, false};
    CreateCondition collection {{10000}, COLLECTION, true, false};
    CreateCondition exact_inscription {{ParseAmount(inscription_amount)}, INSCRIPTION, false, false};
    CreateCondition exact_collection {{ParseAmount(collection_amount)}, COLLECTION, false, false};

//    auto condition = GENERATE_REF(move(inscription), move(collection), move(exact_inscription), move(exact_collection));

    string funds_txid = w->btc().SendToAddress(addr, FormatAmount(10000));
    auto prevout = w->btc().CheckOutput(funds_txid, addr);

    std::string collection_out_pk = Collection::GetCollectionTapRootPubKey(collection_id, hex(new_collection_script_key.GetLocalPrivKey()), hex(new_collection_int_key.GetLocalPrivKey()));

    CreateInscriptionBuilder builder(INSCRIPTION, "0.00000546");
    CHECK_NOTHROW(builder.MiningFeeRate(fee_rate)
                          .Data(content_type, content)
                          .InscribePubKey(hex(destination_pk))
                          .ChangePubKey(hex(destination_pk))
                          .AddUTXO(get<0>(prevout).hash.GetHex(), get<0>(prevout).n, FormatAmount(10000), hex(utxo_key.GetLocalPubKey()))
                          .AddToCollection(collection_id, collection_utxo.m_txid, 0, FormatAmount(546),
                                           hex(collection_script_key.GetLocalPubKey()), hex(collection_int_pk),
                                           collection_out_pk));

    CHECK_NOTHROW(builder.SignCommit(0, hex(utxo_key.GetLocalPrivKey()), hex(script_key.GetLocalPubKey())));
    CHECK_NOTHROW(builder.SignInscription(hex(script_key.GetLocalPrivKey())));
    CHECK_NOTHROW(builder.SignCollection(hex(collection_script_sk)));

    std::string contract = builder.Serialize();
    std::clog << contract << std::endl;

    CreateInscriptionBuilder builder2(INSCRIPTION, "0.00000546");
    builder2.Deserialize(contract);

    stringvector rawtxs;
    CHECK_NOTHROW(rawtxs = builder2.RawTransactions());

    CMutableTransaction commitTx, revealTx;


    REQUIRE(rawtxs.size() == 2);
    REQUIRE(DecodeHexTx(commitTx, rawtxs[0]));
    REQUIRE(DecodeHexTx(revealTx, rawtxs[1]));

    CHECK(revealTx.vout[0].nValue == 546);
    CHECK(revealTx.vout[1].nValue == 546);

    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(commitTx)));
    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(revealTx)));

    collection_utxo = {revealTx.GetHash().GetHex(), 1, 546};
    collection_script_sk = new_collection_script_key.GetLocalPrivKey();
    collection_int_pk = new_collection_int_key.GetLocalPubKey();
}

TEST_CASE("inscribe")
{
    ChannelKeys utxo_key;
    ChannelKeys script_key, inscribe_key;
    ChannelKeys collection_script_key(collection_script_sk);
    ChannelKeys new_collection_script_key, new_collection_int_key;

    string addr = w->bech32().Encode(utxo_key.GetLocalPubKey());

    xonly_pubkey destination_pk = w->bech32().Decode(w->btc().GetNewAddress());

    std::string fee_rate;
    try {
        fee_rate = w->btc().EstimateSmartFee("1");
    }
    catch(...) {
        fee_rate = "0.00001";
    }

    std::clog << "Fee rate: " << fee_rate << std::endl;

    std::string content_type = "text/ascii";
    auto content = hex(GenRandomString(2048));

    CreateInscriptionBuilder test_builder(INSCRIPTION, "0.00000546");
    REQUIRE_NOTHROW(test_builder.MiningFeeRate(fee_rate).Data(content_type, content));

    std::clog << ">>>>> Estimate mining fee <<<<<" << std::endl;

    std::string exact_amount = test_builder.GetMinFundingAmount("");
    std::string exact_amount_w_collection = test_builder.GetMinFundingAmount("collection");

    CreateInscriptionBuilder test_collection(COLLECTION, "0.00000546");
    REQUIRE_NOTHROW(test_collection.MiningFeeRate(fee_rate).Data(content_type, content));
    std::string exact_collection_root_amount = test_collection.GetMinFundingAmount("collection");

    std::clog << "Amount for collection: " << exact_amount_w_collection << std::endl;


    CAmount vin_cost = ParseAmount(test_builder.GetNewInputMiningFee());

    const CreateCondition parent = {{ParseAmount(exact_collection_root_amount)}, COLLECTION, false, true};
    const CreateCondition fund = {{ParseAmount(exact_amount_w_collection)}, INSCRIPTION, false, true};
    const CreateCondition multi_fund = {{ParseAmount(exact_amount_w_collection) - 800, 800 + vin_cost}, INSCRIPTION, false, true};
    const CreateCondition fund_change = {{10000}, INSCRIPTION, true, true};

    auto condition = GENERATE_REF(parent, fund, multi_fund, fund_change);

    CreateInscriptionBuilder builder(condition.type, "0.00000546");
    REQUIRE_NOTHROW(builder.MiningFeeRate(fee_rate).Data(content_type, content));
    REQUIRE_NOTHROW(builder.InscribePubKey(hex(condition.type == COLLECTION ? inscribe_key.GetLocalPubKey() : destination_pk)));
    REQUIRE_NOTHROW(builder.ChangePubKey(hex(destination_pk)));

    for (CAmount amount: condition.funds) {
        const std::string funds_amount = FormatAmount(amount);

        string funds_txid = w->btc().SendToAddress(addr, funds_amount);
        auto prevout = w->btc().CheckOutput(funds_txid, addr);

        REQUIRE_NOTHROW(builder.AddUTXO(get<0>(prevout).hash.GetHex(), get<0>(prevout).n, funds_amount, hex(utxo_key.GetLocalPubKey())));
    }

    if (condition.type == COLLECTION) {
        REQUIRE_NOTHROW(builder.CollectionCommitPubKeys(hex(new_collection_script_key.GetLocalPubKey()), hex(new_collection_int_key.GetLocalPubKey())));
    }

    if (condition.has_parent) {
        std::string collection_out_pk = Collection::GetCollectionTapRootPubKey(collection_id, hex(new_collection_script_key.GetLocalPrivKey()), hex(new_collection_int_key.GetLocalPrivKey()));

        REQUIRE_NOTHROW(builder.AddToCollection(collection_id, collection_utxo.m_txid, collection_utxo.m_nout, FormatAmount(collection_utxo.m_amount),
                                              hex(collection_script_key.GetLocalPubKey()), hex(collection_int_pk),
                                              collection_out_pk));
    }

    for (uint32_t n = 0; n < condition.funds.size(); ++n) {
        std::clog << ">>>>> Sign commit <<<<<" << std::endl;
        REQUIRE_NOTHROW(builder.SignCommit(n, hex(utxo_key.GetLocalPrivKey()), hex(script_key.GetLocalPubKey())));
    }
    if (condition.has_parent) {
        std::clog << ">>>>> Sign collection <<<<<" << std::endl;
        REQUIRE_NOTHROW(builder.SignCollection(hex(collection_script_sk)));
//        CHECK_NOTHROW(builder.SignFundMiningFee(0, hex(extra_key.GetLocalPrivKey())));
    }
    std::clog << ">>>>> Sign inscription <<<<<" << std::endl;
    REQUIRE_NOTHROW(builder.SignInscription(hex(script_key.GetLocalPrivKey())));
    if (condition.type == COLLECTION) {
        REQUIRE_NOTHROW(builder.SignCollectionRootCommit(hex(inscribe_key.GetLocalPrivKey())));
    }

    ChannelKeys rollback_key(unhex<seckey>(builder.getIntermediateTaprootSK()));

    std::string ser_data;
    REQUIRE_NOTHROW(ser_data = builder.Serialize());

    std::clog << ser_data << std::endl;

    CreateInscriptionBuilder builder2(condition.type, "0.00000546");

    std::clog << ">>>>> Deserialize <<<<<" << std::endl;
    REQUIRE_NOTHROW(builder2.Deserialize(ser_data));

    stringvector rawtx;
    REQUIRE_NOTHROW(rawtx = builder2.RawTransactions());

    CMutableTransaction funding_tx, genesis_tx, collection_commit_tx;;
    REQUIRE(DecodeHexTx(funding_tx, rawtx.front()));
    std::clog << "Funding TX ============================================================" << '\n';
    LogTx(funding_tx);
    CHECK(funding_tx.vout.size() == (1 + (condition.has_parent ? 1 : 0) + (condition.has_change ? 1 : 0)));

    REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(funding_tx)));

    SECTION("Inscribe")
    {
        REQUIRE(DecodeHexTx(genesis_tx, rawtx[1]));
        std::clog << "Reveal TX ============================================================" << '\n';
        LogTx(genesis_tx);
        if (condition.type == COLLECTION) {
            REQUIRE(DecodeHexTx(collection_commit_tx, rawtx[2]));
            std::clog << "Collection commit TX ============================================================" << '\n';
            LogTx(collection_commit_tx);
        }
        REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(genesis_tx)));

        if (condition.type == COLLECTION) {
            REQUIRE_NOTHROW(w->btc().SpendTx(CTransaction(collection_commit_tx)));
            CHECK(collection_commit_tx.vout[0].nValue == 546);
        }
        else {
            CHECK(genesis_tx.vout[0].nValue == 546);
        }

        if (condition.type == COLLECTION) {
            collection_id = genesis_tx.GetHash().GetHex() + "i0";
            collection_utxo = {collection_commit_tx.GetHash().GetHex(), 0, collection_commit_tx.vout.front().nValue};
        }
        else if (condition.has_parent){
            collection_utxo = {genesis_tx.GetHash().GetHex(), 1, genesis_tx.vout[1].nValue};
        }

        if (condition.has_parent) {
            if (condition.type == INSCRIPTION) {
                CHECK(funding_tx.vout[0].nValue == 546);
            }

            CHECK(genesis_tx.vout[1].nValue == 546);

            collection_script_sk = new_collection_script_key.GetLocalPrivKey();
            collection_int_pk = new_collection_int_key.GetLocalPubKey();
        }

//        std::optional<Inscription> inscription;
//        CHECK_NOTHROW(inscription = Inscription(rawtx[1], 0));
//        CHECK(inscription->GetIscriptionId() == genesis_tx.GetHash().GetHex() + "i" + std::to_string(0));
//        CHECK(inscription->GetContentType() == content_type);
//        CHECK(inscription->GetContent() == unhex<bytevector>(content));
//
//        if (condition.has_parent) {
//            CHECK(inscription->GetCollectionId() == collection_id);
//        }
    }

    SECTION("Payback")
    {
        CScript rollbackpubkeyscript;
        rollbackpubkeyscript << 1;
        rollbackpubkeyscript << rollback_key.GetLocalPubKey();

        CMutableTransaction rollback_tx;
        rollback_tx.vin.emplace_back(COutPoint(funding_tx.GetHash(), 0));
        rollback_tx.vout.emplace_back(0, rollbackpubkeyscript);

        rollback_tx.vin.front().scriptWitness.stack.emplace_back(64);

        rollback_tx.vout.front().nValue = CalculateOutputAmount(funding_tx.vout.front().nValue, ParseAmount(fee_rate), rollback_tx);

        signature rollback_sig = rollback_key.SignTaprootTx(rollback_tx, 0, {funding_tx.vout.front()}, {});
        rollback_tx.vin.front().scriptWitness.stack.front() = static_cast<bytevector&>(rollback_sig);

        CHECK_NOTHROW(w->btc().SpendTx(CTransaction(rollback_tx)));
    }

    w->btc().GenerateToAddress(w->btc().GetNewAddress(), "1");
}


//TEST_CASE("NotEnoughAmount")
//{
//    //get key pair
//    ChannelKeys utxo_key;
//    ChannelKeys script_key;
//    ChannelKeys dest_key;
//
//    //create address from key pair
//    string addr = w->bech32().Encode(utxo_key.GetLocalPubKey());
//
//    std::string fee_rate;
//    try {
//        fee_rate = w->btc().EstimateSmartFee("1");
//    }
//    catch (...) {
//        fee_rate = "0.000011";
//    }
//    std::clog << "Fee rate: " << fee_rate << std::endl;
//
//    CreateInscriptionBuilder builder("0.00002");
//
//    std::string content_type = "text/ascii";
//    auto content = hex(GenRandomString(1024));
//
//    CHECK_NOTHROW(builder.Data(content_type, content)
//                          .MiningFeeRate(fee_rate));
//
//    std::string lesser_amount = FormatAmount(ParseAmount(builder.GetMinFundingAmount()) - 1);
//
//
//    string txid = w->btc().SendToAddress(addr, lesser_amount);
//    auto prevout = w->btc().CheckOutput(txid, addr);
//
//    CHECK_NOTHROW(builder.AddUTXO(get<0>(prevout).hash.GetHex(), get<0>(prevout).n, lesser_amount, hex(utxo_key.GetLocalPubKey()))
//                         .DestinationPubKey(hex(dest_key.GetLocalPubKey())));
//
//    CHECK_THROWS_AS(builder.SignCommit(0, hex(utxo_key.GetLocalPrivKey()), hex(script_key.GetLocalPubKey())), ContractError);
//
//}
