#include <iostream>
#include <filesystem>
#include <thread>

#include <primitives/transaction.h>
#include <script/script.h>

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

struct TestcaseClient
{
    TestConfigFactory m_confFactory;
    WalletApi m_wallet;

    explicit TestcaseClient() :
            m_confFactory(configpath)
    {

    }
};

struct TestcaseWrapper
{
    TestConfigFactory mConfFactory;
    WalletApi serviceWallet;

    TestcaseClient m_client;

    explicit TestcaseWrapper() :
            mConfFactory(configpath),
            serviceWallet()
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
        std::clog << "Chain trace: " << data.ToString() << std::endl;
    }
};

TEST_CASE_METHOD(TestcaseWrapper, "Simple writing to on-chain service")
{
    auto serviceChainApi = std::make_unique<ChainApi>(Bech32Coder<IBech32Coder::L15, IBech32Coder::REGTEST>(), std::move(mConfFactory.conf.ChainValues(config::L15NODE)), "l15node-cli");
    size_t block_cnt = 0;
    size_t tx_cnt = 0;

    serviceChainApi->CreateWallet("test");

    onchain_service::OnChainService service(std::move(serviceChainApi));

    service.SetNewBlockHandler(ChainTracer<CBlockHeader>{block_cnt});
    service.SetNewTxHandler(ChainTracer<CTransaction>{tx_cnt});

    service.Start();

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

// Service has started
    auto clientChainApi = std::make_shared<ChainApi>(Bech32Coder<IBech32Coder::L15, IBech32Coder::REGTEST>(), std::move(mConfFactory.conf.ChainValues(config::L15NODE)), "l15node-cli");
    ChannelKeys outkey(m_client.m_wallet.Secp256k1Context());

    ChannelKeys key(m_client.m_wallet.Secp256k1Context());
    std::string address = clientChainApi->Bech32Encode(key.GetPubKey());

    UniValue blocks;
    blocks.read(clientChainApi->GenerateToAddress(address, "1"));

    UniValue block;
    block.read(clientChainApi->GetBlock(blocks[0].getValStr(), "1"));

    COutPoint out_point;
    CTxOut tx_out;

    std::tie(out_point, tx_out) = clientChainApi->CheckOutput(block["tx"][0].getValStr(), address);

    CHECK(tx_out.nValue == ParseAmount("4096"));

    CMutableTransaction op_return_tx;
    op_return_tx.vin.emplace_back(CTxIn(out_point));

    CScript outpubkeyscript;
    outpubkeyscript << 1;
    outpubkeyscript << outkey.GetPubKey();

    CScript outopreturnscript;
    outopreturnscript << OP_RETURN;
    outopreturnscript << ParseHex("abcdef1234567890");

    op_return_tx.vout.emplace_back(CTxOut(ParseAmount("4095.99"), outpubkeyscript));
    op_return_tx.vout.emplace_back(CTxOut(0, outopreturnscript));

    bytevector sig = m_client.m_wallet.SignTaprootTx(key.GetLocalPrivKey(), op_return_tx, 0, {tx_out}, {});
    op_return_tx.vin.front().scriptWitness.stack.emplace_back(sig);

    clientChainApi->GenerateToAddress(address, "100"); // Make coinbase tx mature

    CHECK_NOTHROW(clientChainApi->SpendTx(CTransaction(op_return_tx)));
// End of inserted code

    CHECK_NOTHROW(service.Stop());

    std::clog << "On-Chain service is stopped" << std::endl;

    REQUIRE(block_cnt == 101);
    REQUIRE(tx_cnt == 101);
}
