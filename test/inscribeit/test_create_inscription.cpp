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


TEST_CASE("inscribe")
{
    //get key pair
    ChannelKeys utxo_key;
    ChannelKeys dest_key;

    //create address from key pair
    string addr = w->bech32().Encode(utxo_key.GetLocalPubKey());

    //send to the address
    string txid = w->btc().SendToAddress(addr, "0.00001");

    auto prevout = w->btc().CheckOutput(txid, addr);

    std::string fee_rate;
    try {
        fee_rate = w->btc().EstimateSmartFee("1");
    }
    catch(...) {
        fee_rate = "0.000011";
    }

    std::clog << "Fee rate: " << fee_rate << std::endl;

    CreateInscriptionBuilder builder("regtest");

    CHECK_NOTHROW(builder.UTXO(get<0>(prevout).hash.GetHex(), get<0>(prevout).n, FormatAmount(get<1>(prevout).nValue))
                         .Data("text", hex(std::string("test")))
                         .FeeRate(fee_rate)
                         .Destination(hex(dest_key.GetLocalPubKey()))
                         .Sign(hex(utxo_key.GetLocalPrivKey())));

    std::string ser_data;
    CHECK_NOTHROW(ser_data = builder.Serialize());

    std::clog << ser_data << std::endl;

    CreateInscriptionBuilder builder2("regtest");

    CHECK_NOTHROW(builder2.Deserialize(ser_data));

    stringvector rawtx;
    CHECK_NOTHROW(rawtx = builder2.RawTransactions());

    CMutableTransaction funding_tx, genesis_tx;
    CHECK(DecodeHexTx(funding_tx, rawtx.front()));
    CHECK(DecodeHexTx(genesis_tx, rawtx.back()));

    CHECK_NOTHROW(w->btc().SpendTx(CTransaction(funding_tx)));
    CHECK_NOTHROW(w->btc().SpendTx(CTransaction(genesis_tx)));
}

TEST_CASE("inscribe_setters")
{
    //get key pair
    ChannelKeys utxo_key;
    ChannelKeys dest_key;

    //create address from key pair
    string addr = w->bech32().Encode(utxo_key.GetLocalPubKey());

    //send to the address
    string txid = w->btc().SendToAddress(addr, "0.00001");

    auto prevout = w->btc().CheckOutput(txid, addr);

    std::string fee_rate;
    try {
        fee_rate = w->btc().EstimateSmartFee("1");
    }
    catch(...) {
        fee_rate = "0.000011";
    }

    std::clog << "Fee rate: " << fee_rate << std::endl;

    CreateInscriptionBuilder builder("regtest");

    builder.SetUtxoTxId(get<0>(prevout).hash.GetHex());
    builder.SetUtxoNOut(get<0>(prevout).n);
    builder.SetUtxoAmount(FormatAmount(get<1>(prevout).nValue));
    builder.SetMiningFeeRate(fee_rate);
    builder.SetContentType("text");
    builder.SetContent(hex(std::string("test")));
    builder.SetDestinationPubKey(hex(dest_key.GetLocalPubKey()));

    CHECK_NOTHROW(builder.Sign(hex(utxo_key.GetLocalPrivKey())));

    std::string ser_data;
    CHECK_NOTHROW(ser_data = builder.Serialize());

    std::clog << ser_data << std::endl;

    CreateInscriptionBuilder builder2("regtest");

    CHECK_NOTHROW(builder2.Deserialize(ser_data));

    stringvector rawtx;
    CHECK_NOTHROW(rawtx = builder2.RawTransactions());

    CMutableTransaction funding_tx, genesis_tx;
    CHECK(DecodeHexTx(funding_tx, rawtx.front()));
    CHECK(DecodeHexTx(genesis_tx, rawtx.back()));

    CHECK_NOTHROW(w->btc().SpendTx(CTransaction(funding_tx)));
    CHECK_NOTHROW(w->btc().SpendTx(CTransaction(genesis_tx)));
}

TEST_CASE("fallback")
{
    //get key pair
    ChannelKeys utxo_key;
    ChannelKeys dest_key;

    //create address from key pair
    string addr = w->bech32().Encode(utxo_key.GetLocalPubKey());

    //send to the address
    string txid = w->btc().SendToAddress(addr, "0.00001");

    auto prevout = w->btc().CheckOutput(txid, addr);

    std::string fee_rate;
    try {
        fee_rate = w->btc().EstimateSmartFee("1");
    }
    catch(...) {
        fee_rate = "0.000011";
    }

    std::clog << "Fee rate: " << fee_rate << std::endl;

    CreateInscriptionBuilder builder("regtest");

    CHECK_NOTHROW(builder.UTXO(get<0>(prevout).hash.GetHex(), get<0>(prevout).n, FormatAmount(get<1>(prevout).nValue))
                          .Data("text", hex(std::string("test")))
                          .FeeRate(fee_rate)
                          .Destination(hex(dest_key.GetLocalPubKey()))
                          .Sign(hex(utxo_key.GetLocalPrivKey())));

    ChannelKeys rollback_key(unhex<seckey>(builder.IntermediateTaprootPrivKey()));

    std::string ser_data;
    CHECK_NOTHROW(ser_data = builder.Serialize());

    std::clog << ser_data << std::endl;

    CreateInscriptionBuilder builder2("regtest");

    CHECK_NOTHROW(builder2.Deserialize(ser_data));

    stringvector rawtx;
    CHECK_NOTHROW(rawtx = builder2.RawTransactions());

    CMutableTransaction funding_tx, genesis_tx;
    CHECK(DecodeHexTx(funding_tx, rawtx.front()));
    CHECK(DecodeHexTx(genesis_tx, rawtx.back()));

    CHECK_NOTHROW(w->btc().SpendTx(CTransaction(funding_tx)));

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
