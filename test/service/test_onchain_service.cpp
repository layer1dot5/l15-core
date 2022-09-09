#include <iostream>
#include <filesystem>
#include <thread>

#define CATCH_CONFIG_RUNNER
#include "catch/catch.hpp"

#include "util/translation.h"
#include "univalue.h"

#include "config.hpp"
#include "nodehelper.hpp"
#include "exechelper.hpp"
#include "wallet_api.hpp"
#include "chain_api.hpp"
#include "channel_keys.hpp"
#include "onchain_service.hpp"

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
    WalletApi wallet;


    explicit TestcaseWrapper() :
            mConfFactory(configpath),
            wallet()
            //node(Bech32Coder<IBech32Coder::L15, IBech32Coder::REGTEST>(), std::move(mConfFactory.conf.ChainValues(config::L15NODE)), "l15node-cli")
    {
        try {
            StartNode();
        }
        catch (...) {
            CleanUpNode();
            StartNode();
        }
     }

    ~TestcaseWrapper()
    {
        CleanUpNode();
    }

    void CleanUpNode() {
        ExecHelper cli("l15node-cli", false);
        StopNode(ChainMode::MODE_REGTEST, cli, conf().Subcommand(config::L15CLIENT));
        std::filesystem::remove_all(mConfFactory.GetDataDir() + "/regtest");
    }

    void StartNode() {
        ExecHelper node("l15noded", false);
        l15::StartNode(ChainMode::MODE_REGTEST, node, conf().Subcommand(config::L15NODE));
    }

    Config& conf() { return mConfFactory.conf; }
};


template <class D>
struct ChainTracer {
    size_t& counter;

    void operator()(const D& data)
    {
        ++counter;
        std::clog << data.ToString() << std::endl;
    }
};

TEST_CASE_METHOD(TestcaseWrapper, "Start/stop on-chain service")
{
    auto chain = std::make_unique<ChainApi>(Bech32Coder<IBech32Coder::L15, IBech32Coder::REGTEST>(), std::move(mConfFactory.conf.ChainValues(config::L15NODE)), "l15node-cli");
    size_t block_cnt = 0;
    size_t tx_cnt = 0;

    chain->CreateWallet("test");

    onchain_service::OnChainService service(std::move(chain));

    service.SetNewBlockHandler(ChainTracer<CBlockHeader>{block_cnt});
    service.SetNewTxHandler(ChainTracer<CTransaction>{tx_cnt});

    service.Start();

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    service.ChainAPI().GenerateToAddress(service.ChainAPI().GetNewAddress(), "2");

    std::this_thread::sleep_for(std::chrono::seconds(5));

    CHECK_NOTHROW(service.Stop());

    std::clog << "On-Chain service is stopped" << std::endl;

    REQUIRE(block_cnt == 2);
    REQUIRE(tx_cnt == 2);
}
