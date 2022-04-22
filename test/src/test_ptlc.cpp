#include <iostream>
#include <filesystem>

#define CATCH_CONFIG_RUNNER
#include "catch.hpp"

#include "util/translation.h"
#include "tools/config.hpp"
#include "tools/nodehelper.hpp"
#include "core/chain_api.hpp"
#include "core/wallet_api.hpp"

using namespace l15;
const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

std::string configpath;

int main(int argc, char* argv[])
{
    Catch::Session session;


    // Build a new parser on top of Catch's
    using namespace Catch::clara;
    auto cli
            = session.cli() // Get Catch's composite command line parser
              | Opt(configpath, "Config path") // bind variable to a new option, with a hint string
              ["--config"]    // the option names it will respond to
                      ("Path to bitcoin config");

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

    return session.run();
}


struct TestConfigFactory
{
    Config conf;

    explicit TestConfigFactory(const std::string &confpath)
    {
        conf.ProcessConfig({"--conf=" + confpath});
    }

    api::ChainMode GetChainMode() const
    {
        return api::ChainMode::MODE_REGTEST;
    }

    const std::string GetBitcoinDataDir() const
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
    api::ChainMode mMode;
    api::WalletApi mWallet;
    api::ChainApi mBtc;
//    channelhtlc_ptr mChannelForAliceSide;
//    channelhtlc_ptr mChannelForCarolSide;

    explicit TestcaseWrapper(const std::string &confpath) :
            mConfFactory(confpath),
            mMode(mConfFactory.GetChainMode()),
            mWallet(mConfFactory.GetChainMode()),
            mBtc(mWallet, std::move(mConfFactory.conf.BitcoinValues()), "l15node-cli")
    {
        StartBitcoinNode();

        if(btc().GetChainHeight() < 50)
        {
            btc().CreateWallet("testwallet");
            btc().GenerateToOwnAddress("250");
        }
    }

    ~TestcaseWrapper()
    {
        StopBitcoinNode();
        std::filesystem::remove_all(mConfFactory.GetBitcoinDataDir() + "/regtest");
    }

    void StartBitcoinNode()
    {
        StartNode(mConfFactory.GetChainMode(), "bitcoind", conf().Subcommand(config::BITCOIND));
    }

    void StopBitcoinNode()
    {
        StopNode(mMode, "l15node-cli", conf().Subcommand(config::BITCOIN));
    }

    Config &conf()
    { return mConfFactory.conf; }

    api::WalletApi &wallet()
    { return mWallet; }

    api::ChainApi &btc()
    { return mBtc; }
//    ChannelHtlc& channel_for_alice() { return *mChannelForAliceSide; }
//    ChannelHtlc& channel_for_carol() { return *mChannelForCarolSide; }

    void ResetMemPool()
    {
        StopBitcoinNode();

        std::filesystem::remove(mConfFactory.GetBitcoinDataDir() + "/regtest/mempool.dat");

        StartBitcoinNode();
    }

};

TEST_CASE("PTLC simple positive cases")
{
    TestcaseWrapper w(configpath);
}
