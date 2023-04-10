#include <iostream>
#include <filesystem>
#include <algorithm>

#define CATCH_CONFIG_RUNNER
#include "catch/catch.hpp"

#include "core_io.h"
#include "policy/policy.h"
#include "util/translation.h"

#include "config.hpp"
#include "nodehelper.hpp"
#include "chain_api.hpp"
#include "wallet_api.hpp"
#include "channel_keys.hpp"
#include "exechelper.hpp"
#include "swap_inscription.hpp"
#include "fee_calculator.hpp"

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
        /*StartBitcoinNode();

        if(btc().GetChainHeight() < 50)
        {
            btc().CreateWallet("testwallet");
            btc().GenerateToAddress(btc().GetNewAddress(), "150");
        }*/
    }

    virtual ~TestcaseWrapper()
    {
        //StopBitcoinNode();
        //std::filesystem::remove_all(mConfFactory.GetBitcoinDataDir() + "/regtest");
    }

    void StartBitcoinNode()
    {
        //StartNode(ChainMode::MODE_REGTEST, mBtcd, conf().Subcommand(config::BITCOIND));
    }

    void StopBitcoinNode()
    {
        //StopNode(ChainMode::MODE_REGTEST, mCli, conf().Subcommand(config::BITCOIN));
    }

    Config &conf()
    { return mConfFactory.conf; }

    WalletApi &wallet()
    { return mWallet; }

    ChainApi &btc()
    { return mBtc; }

    void ResetMemPool()
    {
        /*StopBitcoinNode();
        std::filesystem::remove(mConfFactory.GetBitcoinDataDir() + "/regtest/mempool.dat");
        StartBitcoinNode();*/
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

TEST_CASE("FeeCalculatorInitialization")
{
    l15::inscribeit::FeeCalculator feeCalculator;

    CAmount fee;
    REQUIRE_NOTHROW(fee = feeCalculator.getFee("0.000015", l15::inscribeit::TransactionKind::FundsCommit));
    CHECK(fee == 162);

    REQUIRE_NOTHROW(fee = feeCalculator.getFee("0.000015", l15::inscribeit::TransactionKind::OrdinalCommit));
    CHECK(fee == 162);

    REQUIRE_NOTHROW(fee = feeCalculator.getFee("0.000015", l15::inscribeit::TransactionKind::OrdinalTransfer));
    CHECK(fee == 162);

    REQUIRE_NOTHROW(fee = feeCalculator.getFee("0.000015", l15::inscribeit::TransactionKind::OrdinalSwap));
    CHECK(fee == 544);
}

TEST_CASE("FeeCalculatorNotImplemented")
{
    l15::inscribeit::FeeCalculator feeCalculator;
    REQUIRE_THROWS_AS(feeCalculator.getFee("0.000015", l15::inscribeit::TransactionKind::NotImplemented), l15::TransactionError);
}
