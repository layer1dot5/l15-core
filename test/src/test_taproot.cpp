#include <iostream>
#include <filesystem>
#include <algorithm>

#define CATCH_CONFIG_RUNNER
#include "catch/catch.hpp"

#include "util/translation.h"
#include "tools/config.hpp"
#include "tools/nodehelper.hpp"
#include "core/chain_api.hpp"
#include "core/wallet_api.hpp"
#include "core/channel_keys.hpp"
#include "core/exechelper.hpp"
#include "utils.hpp"
#include "script_merkle_tree.hpp"

using namespace l15;
using namespace l15::core;

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

class TestcaseWrapper;

std::string configpath;
std::unique_ptr<TestcaseWrapper> w;

struct TestConfigFactory
{
    Config conf;

    explicit TestConfigFactory(const std::string &confpath)
    {
        conf.ProcessConfig({"--conf=" + confpath});
    }

    std::string GetBitcoinDataDir() const
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
    WalletApi mWallet;
    ChainApi mBtc;
    ExecHelper mCli;
    ExecHelper mBtcd;
//    channelhtlc_ptr mChannelForAliceSide;
//    channelhtlc_ptr mChannelForCarolSide;

    explicit TestcaseWrapper() :
            mConfFactory(configpath),
            mWallet(),
            mBtc(Bech32Coder<IBech32Coder::BTC, IBech32Coder::REGTEST>(), std::move(mConfFactory.conf.ChainValues(config::BITCOIN)), "l15node-cli"),
            mCli("l15node-cli", false),
            mBtcd("bitcoind", false)

    {
        StartBitcoinNode();

        if(btc().GetChainHeight() < 50)
        {
            btc().CreateWallet("testwallet");
            btc().GenerateToAddress(btc().GetNewAddress(), "250");
        }
    }

    virtual ~TestcaseWrapper()
    {
        StopBitcoinNode();
        std::filesystem::remove_all(mConfFactory.GetBitcoinDataDir() + "/regtest");
    }

    void StartBitcoinNode()
    {
        StartNode(ChainMode::MODE_REGTEST, mBtcd, conf().Subcommand(config::BITCOIND));
    }

    void StopBitcoinNode()
    {
        StopNode(ChainMode::MODE_REGTEST, mCli, conf().Subcommand(config::BITCOIN));
    }

    Config &conf()
    { return mConfFactory.conf; }

    WalletApi &wallet()
    { return mWallet; }

    ChainApi &btc()
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

    SECTION("Taproot public key path spending")
    {
        //get key pair
        auto sk = ChannelKeys(w->wallet().Secp256k1Context());
        auto& pk = sk.GetLocalPubKey();

        //create address from key pair
        string addr = w->btc().Bech32Encode(pk);

        //send to the address
        string txid = w->btc().SendToAddress(addr, "1.001");

        auto prevout = w->btc().CheckOutput(txid, addr);

        // create new wallet associated address
        string backaddr = w->btc().GetNewAddress();

        //spend first transaction to the last address

        auto backpk = w->btc().Bech32Decode(backaddr);

        std::clog << "Payoff PK: " << HexStr(backpk) << std::endl;

        CMutableTransaction tx;

        CScript outpubkeyscript;
        outpubkeyscript << 1;
        outpubkeyscript << backpk;

        CTxOut out(ParseAmount("1"), outpubkeyscript);
        tx.vout.emplace_back(out);

        tx.vin.emplace_back(CTxIn(std::get<0>(prevout)));

        std::vector<CTxOut> prevtxouts = {std::get<1>(prevout)};

        bytevector sig = w->wallet().SignTaprootTx(sk.GetLocalPrivKey(), tx, 0, std::move(prevtxouts), {});

        std::clog << "Signature: " << HexStr(sig) << std::endl;

        tx.vin.front().scriptWitness.stack.emplace_back(sig);

        CHECK_NOTHROW(w->btc().SpendTx(CTransaction(tx)));
    }

    SECTION("Taproot script path spending")
    {
        //get key pair Taproot
        auto internal_sk = ChannelKeys(w->wallet().Secp256k1Context());
        const auto& internal_pk = internal_sk.GetLocalPubKey();

        std::clog << "\nInternal PK: " << HexStr(internal_pk) << std::endl;

        //get key pair script
        auto sk = ChannelKeys(w->wallet().Secp256k1Context());
        const auto& pk = sk.GetLocalPubKey();
        std::string pk_str = HexStr(pk);

        std::clog << "\nScript pubkey: " << pk_str << std::endl;

        //Create script merkle tree
        CScript script;
        script << ParseHex(pk_str);
        script << OP_CHECKSIG;

        ScriptMerkleTree tap_tree (TreeBalanceType::WEIGHTED, {script});
        uint256 root = tap_tree.CalculateRoot();

        std::clog << "\nTapLeaf hash: " << HexStr(TapLeafHash(script)) << std::endl;
        std::clog << "TapTree root: " << HexStr(root) << std::endl;

        xonly_pubkey taprootpubkey;
        uint8_t taprootpubkeyparity;

        std::tie(taprootpubkey, taprootpubkeyparity) = internal_sk.AddTapTweak(root);
        string addr = w->btc().Bech32Encode(taprootpubkey);

        std::clog << "\nTaproot PK: " << HexStr(taprootpubkey) << std::endl;
        std::clog << "Taptweak parity flag: " << (int)taprootpubkeyparity << std::endl;
        std::clog << "Taproot address: " << addr << std::endl;

        //send to the address
        string txid = w->btc().SendToAddress(addr, "1.001");

        auto prevout = w->btc().CheckOutput(txid, addr);

        // create new wallet associated address
        string backaddr = w->btc().GetNewAddress();

        //spend first transaction to the last address

        auto backpk = w->btc().Bech32Decode(backaddr);

        std::clog << "Payoff PK: " << HexStr(backpk) << std::endl;

        CMutableTransaction tx;

        CScript outpubkeyscript;
        outpubkeyscript << 1;
        outpubkeyscript << backpk;

        CTxOut out(ParseAmount("1"), outpubkeyscript);
        tx.vout.emplace_back(out);

        tx.vin.emplace_back(CTxIn(std::get<0>(prevout)));

        std::vector<CTxOut> prevtxouts = {std::get<1>(prevout)};

        bytevector sig = w->wallet().SignTaprootTx(sk.GetLocalPrivKey(), tx, 0, std::move(prevtxouts), script);

        std::clog << "Signature: " << HexStr(sig) << std::endl;

        tx.vin.front().scriptWitness.stack.emplace_back(sig);
        tx.vin.front().scriptWitness.stack.emplace_back(bytevector(script.begin(), script.end()));

        auto scriptpath = tap_tree.CalculateScriptPath(script);

        bytevector controlblock = {static_cast<uint8_t>(0xc0 | taprootpubkeyparity)};
        controlblock.reserve(1 + internal_pk.size() + scriptpath.size() * uint256::size());
        controlblock.insert(controlblock.end(), internal_pk.begin(), internal_pk.end());

        std::for_each(scriptpath.begin(), scriptpath.end(), [&](uint256 &branchhash)
            {
                controlblock.insert(controlblock.end(), branchhash.begin(), branchhash.end());
            });

        tx.vin.front().scriptWitness.stack.emplace_back(controlblock);

        CHECK_NOTHROW(w->btc().SpendTx(CTransaction(tx)));
    }
}
