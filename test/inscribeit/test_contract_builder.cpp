#include <iostream>
#include <filesystem>
#include <algorithm>
#include <vector>

#define CATCH_CONFIG_RUNNER
#include "catch/catch.hpp"

#include "util/translation.h"
#include "config.hpp"
#include "nodehelper.hpp"
#include "chain_api.hpp"
#include "wallet_api.hpp"
#include "channel_keys.hpp"
#include "exechelper.hpp"
#include "swap_inscription.hpp"
#include "core_io.h"

#include "policy/policy.h"

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

//    if(configpath.empty())
//    {
//        std::cerr << "Bitcoin config is not passed!" << std::endl;
//        return 1;
//    }
//
//    std::filesystem::path p(configpath);
//    if(p.is_relative())
//    {
//        configpath = (std::filesystem::current_path() / p).string();
//    }
//
//    w = std::make_unique<TestcaseWrapper>(configpath);

    return session.run();
}


TEST_CASE("Fee")
{
    CMutableTransaction tx;

    CAmount base_fee = CalculateTxFee(1000, tx);

    std::clog << "Base tx vsize (no vin/vout): " << base_fee << std::endl;

    tx.vin.emplace_back(uint256(), 0);
    tx.vin.back().scriptWitness.stack.emplace_back(64);
    tx.vout.emplace_back(0, CScript() << 1 << xonly_pubkey());

    CAmount min_fee = CalculateTxFee(1000, tx);

    std::clog << "Mininal taproot tx vsize: " << min_fee << std::endl;

    tx.vin.emplace_back(uint256(), 0);
    tx.vin.back().scriptWitness.stack.emplace_back(64);

    CAmount double_vin_fee = CalculateTxFee(1000, tx);
    std::clog << "Key spend path taproot vin vsize: " << (double_vin_fee - min_fee) << std::endl;

    tx.vout.emplace_back(0, CScript() << 1 << xonly_pubkey());

    CAmount double_vout_fee = CalculateTxFee(1000, tx);
    std::clog << "Taproot vout vsize: " << (double_vout_fee - double_vin_fee) << std::endl;

}

