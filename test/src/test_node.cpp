#include <iostream>
#include <filesystem>

#define CATCH_CONFIG_RUNNER
#include "catch.hpp"

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
    api::ChainMode GetChainMode() const
    {
        return api::ChainMode::MODE_REGTEST;
    }
    const std::string GetDataDir() const
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
    api::ChainMode mMode;
//    api::ChainApi mBtc;

    explicit TestcaseWrapper(const std::string& confpath) :
        mConfFactory(confpath),
        mMode(mConfFactory.GetChainMode())
        //mBtc(mWallet, std::vector<std::string>(mConfFactory.conf.BitcoinValues()))
    {

//        if (btc().GetChainHeight() < 50)
//        {
//            btc().CreateWallet("testwallet");
//            btc().GenerateToOwnAddress("250");
//        }
    }

    ~TestcaseWrapper()
    {
        StopNode(mConfFactory.GetChainMode(), "l15node-cli", conf().Subcommand(config::L15CLIENT));
        std::filesystem::remove_all(mConfFactory.GetDataDir() + "/regtest");
    }

    void startNode() {
        StartNode(mConfFactory.GetChainMode(), "l15noded", conf().Subcommand(config::L15NODE));
    }


    Config& conf() { return mConfFactory.conf; }
 //   api::WalletApi& wallet() { return mWallet; }
//    api::ChainApi& btc() { return mBtc; }

};

TEST_CASE("Run l15-node") {
    TestcaseWrapper w(configpath);

    w.startNode();

}

