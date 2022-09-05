#include <iostream>
#include <filesystem>
#include <memory>
#include <algorithm>

#define CATCH_CONFIG_RUNNER
#include "catch/catch.hpp"

#include "util/translation.h"

#include "config.hpp"
#include "nodehelper.hpp"
#include "channel.hpp"
#include "wallet_api.hpp"
#include "utils.hpp"
#include "script_merkle_tree.hpp"

#include "test_suite_node.hpp"
#include "test_suite_channel.hpp"

using namespace l15;
const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

class TestcaseWrapper;

std::string configpath;
std::unique_ptr<TestcaseWrapper> w;


class TestcaseWrapper : public NodeWrapper, ChannelWrapper
{

public:
    explicit TestcaseWrapper() :
            NodeWrapper(configpath, "l15node-cli", "bitcoind", config::BITCOIN, config::BITCOIND)

    {
        start_node();

        if(btc().GetChainHeight() < 50)
        {
            btc().CreateWallet("testwallet");
            btc().GenerateToOwnAddress("250");
        }

        open_channel(btc());

    }

    virtual ~TestcaseWrapper()
    {
        close_channel();
        stop_node();
        std::filesystem::remove_all(mConfFactory.GetBitcoinDataDir() + "/regtest");
    }


    void ResetMemPool()
    {
        stop_node();

        std::filesystem::remove(mConfFactory.GetBitcoinDataDir() + "/regtest/mempool.dat");

        start_node();
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



TEST_CASE("Taproot transaction test cases")
{


}
