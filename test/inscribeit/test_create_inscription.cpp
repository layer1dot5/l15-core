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
};

TEST_CASE("inscribe")
{
    //get key pair
    ChannelKeys utxo_key;
    ChannelKeys script_key;

    xonly_pubkey destination_pk = w->bech32().Decode(w->btc().GetNewAddress());

    std::string fee_rate;
    try {
        fee_rate = w->btc().EstimateSmartFee("1");
    }
    catch(...) {
        fee_rate = "0.000011";
    }

    std::clog << "Fee rate: " << fee_rate << std::endl;

    std::string content_type = "text/ascii";
    auto content = hex(GenRandomString(1024));

    CreateInscriptionBuilder builder("0.00002");
    CHECK_NOTHROW(builder.MiningFeeRate(fee_rate).Data(content_type, content));

    std::string exact_amount = builder.GetMinFundingAmount();

    const CreateCondition fund = {{70000}};
    const CreateCondition exact_fund = {{ParseAmount(exact_amount)}};
    const CreateCondition multi_fund = {{ParseAmount(exact_amount), 1500}};

    auto condition = GENERATE_REF(fund, exact_fund, multi_fund);

    //create address from key pair
    string addr = w->bech32().Encode(utxo_key.GetLocalPubKey());


    for (CAmount amount: condition.funds) {
        const std::string funds_amount = FormatAmount(amount);

        string funds_txid = w->btc().SendToAddress(addr, funds_amount);
        auto prevout = w->btc().CheckOutput(funds_txid, addr);

        CHECK_NOTHROW(builder.AddUTXO(get<0>(prevout).hash.GetHex(), get<0>(prevout).n, funds_amount, hex(utxo_key.GetLocalPubKey())));
    }

    CHECK_NOTHROW(builder.DestinationPubKey(hex(destination_pk)));

    for (uint32_t n = 0; n < condition.funds.size(); ++n) {
        CHECK_NOTHROW(builder.SignCommit(n, hex(utxo_key.GetLocalPrivKey()), hex(script_key.GetLocalPubKey())));
    }
    CHECK_NOTHROW(builder.SignInscription(hex(script_key.GetLocalPrivKey())));

    ChannelKeys rollback_key(unhex<seckey>(builder.getIntermediateTaprootSK()));

    std::string ser_data;
    CHECK_NOTHROW(ser_data = builder.Serialize());

    std::clog << ser_data << std::endl;

    CreateInscriptionBuilder builder2("0.00002");

    CHECK_NOTHROW(builder2.Deserialize(ser_data));

    stringvector rawtx;
    CHECK_NOTHROW(rawtx = builder2.RawTransactions());

    CMutableTransaction funding_tx;
    CHECK(DecodeHexTx(funding_tx, rawtx.front()));
    CHECK_NOTHROW(w->btc().SpendTx(CTransaction(funding_tx)));

    SECTION("Inscribe")
    {
        CMutableTransaction genesis_tx;
        CHECK(DecodeHexTx(genesis_tx, rawtx.back()));

        CHECK_NOTHROW(w->btc().SpendTx(CTransaction(genesis_tx)));
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
}


TEST_CASE("NotEnoughAmount")
{
    //get key pair
    ChannelKeys utxo_key;
    ChannelKeys script_key;
    ChannelKeys dest_key;

    //create address from key pair
    string addr = w->bech32().Encode(utxo_key.GetLocalPubKey());

    std::string fee_rate;
    try {
        fee_rate = w->btc().EstimateSmartFee("1");
    }
    catch (...) {
        fee_rate = "0.000011";
    }
    std::clog << "Fee rate: " << fee_rate << std::endl;

    CreateInscriptionBuilder builder("0.00002");

    std::string content_type = "text/ascii";
    auto content = hex(GenRandomString(1024));

    CHECK_NOTHROW(builder.Data(content_type, content)
                          .MiningFeeRate(fee_rate));

    std::string lesser_amount = FormatAmount(ParseAmount(builder.GetMinFundingAmount()) - 1);


    string txid = w->btc().SendToAddress(addr, lesser_amount);
    auto prevout = w->btc().CheckOutput(txid, addr);

    CHECK_NOTHROW(builder.AddUTXO(get<0>(prevout).hash.GetHex(), get<0>(prevout).n, lesser_amount, hex(utxo_key.GetLocalPubKey()))
                         .DestinationPubKey(hex(dest_key.GetLocalPubKey())));

    CHECK_THROWS_AS(builder.SignCommit(0, hex(utxo_key.GetLocalPrivKey()), hex(script_key.GetLocalPubKey())), ContractError);

}
