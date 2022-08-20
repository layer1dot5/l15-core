#include <iostream>
#include <filesystem>

#define CATCH_CONFIG_RUNNER
#include "catch/catch.hpp"

#include "util/translation.h"
#include "tools/config.hpp"
#include "tools/nodehelper.hpp"
#include "core/exechelper.hpp"
#include "core/wallet_api.hpp"
#include "core/chain_api.hpp"

using namespace l15;
using namespace l15::core;

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

std::string configpath;

int main(int argc, char* argv[])
{
    Catch::Session session;


    // Build a new parser on top of Catch's
    using namespace Catch::clara;
    auto cli
            = session.cli() // Get Catch's composite command line parser
              | Opt(configpath, "Config path" ) // bind variable to a new option, with a hint string
              ["--config"]    // the option names it will respond to
                      ("Path to node config");

    session.cli( cli );

    // Let Catch (using Clara) parse the command line
    int returnCode = session.applyCommandLine(argc, argv);
    if( returnCode != 0 ) // Indicates a command line error
        return returnCode;

    if(configpath.empty())
    {
        std::cerr << "Config path is not passed!" << std::endl;
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
    explicit TestConfigFactory(const std::string& confpath)
    {
        std::clog << "Config: " << confpath << std::endl;
        conf.ProcessConfig({"--conf=" + confpath});
        std::clog << "Config has been processed" << std::endl;
    }
    std::string GetDataDir() const
    {
        auto datadir_opt = conf.Subcommand(config::L15NODE).get_option(config::option::DATADIR);
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
    ChainApi mNode;

    explicit TestcaseWrapper() :
        mConfFactory(configpath),
        mWallet(),
        mNode(Bech32Coder<IBech32Coder::L15, IBech32Coder::REGTEST>(), std::move(mConfFactory.conf.ChainValues(config::L15NODE)), "l15node-cli")
    {
        startNode();
    }

    ~TestcaseWrapper()
    {
        ExecHelper cli("l15node-cli", false);
        StopNode(ChainMode::MODE_REGTEST, cli, conf().Subcommand(config::L15CLIENT));
        std::filesystem::remove_all(mConfFactory.GetDataDir() + "/regtest");
    }

    void startNode() {
        ExecHelper node("l15noded", false);
        StartNode(ChainMode::MODE_REGTEST, node, conf().Subcommand(config::L15NODE));
    }

    Config& conf() { return mConfFactory.conf; }
};

TEST_CASE_METHOD(TestcaseWrapper, "Start/stop l15-node")
{ }

TEST_CASE_METHOD(TestcaseWrapper, "Mint l15SR coins")
{

}
