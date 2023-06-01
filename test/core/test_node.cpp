#include <iostream>
#include <filesystem>

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

#include "test_case_wrapper.hpp"

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


TEST_CASE("Start/stop l15-node")
{ }

TEST_CASE("Test transactions")
{
    ChannelKeys outkey;

    ChannelKeys key;
    std::string address = w->bech32().Encode(key.GetPubKey());

    UniValue blocks;
    blocks.read(w->btc().GenerateToAddress(address, "1"));

    UniValue block;
    block.read(w->btc().GetBlock(blocks[0].getValStr(), "1"));

    COutPoint out_point;
    CTxOut tx_out;

    std::tie(out_point, tx_out) = w->btc().CheckOutput(block["tx"][0].getValStr(), address);

    CHECK(tx_out.nValue == ParseAmount("4096"));

    CMutableTransaction op_return_tx;
    op_return_tx.vin.emplace_back(out_point);

    CScript outpubkeyscript;
    outpubkeyscript << 1;
    outpubkeyscript << outkey.GetPubKey();

    CScript outopreturnscript;
    outopreturnscript << OP_RETURN;
    outopreturnscript << ParseHex("db1ff3f207771e90ec30747525abaefd3b56ff2b3aecbb76809b7106617c442e");

    op_return_tx.vout.emplace_back(ParseAmount("4095.99"), outpubkeyscript);
    op_return_tx.vout.emplace_back(0, outopreturnscript);

    bytevector sig = key.SignTaprootTx(op_return_tx, 0, {tx_out}, {});
    op_return_tx.vin.front().scriptWitness.stack.emplace_back(sig);

    w->btc().GenerateToAddress(address, "100"); // Make coinbase tx mature

    CHECK_NOTHROW(w->btc().SpendTx(CTransaction(op_return_tx)));

}
