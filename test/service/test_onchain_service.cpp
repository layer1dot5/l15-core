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
#include "schnorr.hpp"
#include "onchain_service.hpp"

#include "test_case_wrapper.hpp

using namespace l15;
using namespace l15::core;

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

    w = std::make_unique<TestcaseWrapper>(configpath, "l15node-cli");

    return session.run();
}

template <class D>
struct ChainTracer {
    size_t& counter;

    void operator()(const D& data)
    {
        ++counter;
        std::clog << data.ToString() << std::endl;
    }
};

TEST_CASE("Start/stop on-chain service")
{
    auto chain = std::make_unique<ChainApi>(std::move(mConfFactory.conf.ChainValues(config::L15NODE)), "l15node-cli");
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
