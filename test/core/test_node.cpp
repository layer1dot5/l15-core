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
    ChainApi node;

    explicit TestcaseWrapper() :
            mConfFactory(configpath),
            wallet(),
            node(Bech32Coder<IBech32Coder::L15, IBech32Coder::REGTEST>(), std::move(mConfFactory.conf.ChainValues(config::L15NODE)), "l15node-cli")
    {
        StartNode();
    }

    ~TestcaseWrapper()
    {
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

TEST_CASE_METHOD(TestcaseWrapper, "Start/stop l15-node")
{ }

TEST_CASE_METHOD(TestcaseWrapper, "Test transactions")
{
    ChannelKeys outkey(wallet.Secp256k1Context());

    ChannelKeys key(wallet.Secp256k1Context());
    std::string address = node.Bech32Encode(key.GetPubKey());

    UniValue blocks;
    blocks.read(node.GenerateToAddress(address, "1"));

    UniValue block;
    block.read(node.GetBlock(blocks[0].getValStr(), "1"));

    COutPoint out_point;
    CTxOut tx_out;

    std::tie(out_point, tx_out) = node.CheckOutput(block["tx"][0].getValStr(), address);

    CHECK(tx_out.nValue == ParseAmount("4096"));

    CMutableTransaction op_return_tx;
    op_return_tx.vin.emplace_back(CTxIn(out_point));

    CScript outpubkeyscript;
    outpubkeyscript << 1;
    outpubkeyscript << outkey.GetPubKey();

    CScript outopreturnscript;
    outopreturnscript << OP_RETURN;
    outopreturnscript << ParseHex("db1ff3f207771e90ec30747525abaefd3b56ff2b3aecbb76809b7106617c442e");

    op_return_tx.vout.emplace_back(CTxOut(ParseAmount("4095.99"), outpubkeyscript));
    op_return_tx.vout.emplace_back(CTxOut(0, outopreturnscript));

    bytevector sig = wallet.SignTaprootTx(key.GetLocalPrivKey(), op_return_tx, 0, {tx_out}, {});
    op_return_tx.vin.front().scriptWitness.stack.emplace_back(sig);

    node.GenerateToAddress(address, "100"); // Make coinbase tx mature

    CHECK_NOTHROW(node.SpendTx(CTransaction(op_return_tx)));
    //CHECK_NOTHROW(node.SpendTx(CTransaction(op_return_tx)));

}
