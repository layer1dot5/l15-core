#include <iostream>
#include <filesystem>
#include <memory>
#include <algorithm>

#define CATCH_CONFIG_RUNNER
#include "catch/catch.hpp"

#include "util/translation.h"
#include "tools/config.hpp"
#include "tools/nodehelper.hpp"
#include "core/chain_api.hpp"
#include "core/wallet_api.hpp"
#include "core/exechelper.hpp"
#include "utils.hpp"
#include "script_merkle_tree.hpp"

using namespace l15;
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

    api::ChainMode GetChainMode() const
    {
        return api::ChainMode::MODE_REGTEST;
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
    api::ChainMode mMode;
    api::WalletApi mWallet;
    api::ChainApi mBtc;
    ExecHelper mCli;
    ExecHelper mBtcd;
//    channelhtlc_ptr mChannelForAliceSide;
//    channelhtlc_ptr mChannelForCarolSide;

    explicit TestcaseWrapper() :
            mConfFactory(configpath),
            mMode(mConfFactory.GetChainMode()),
            mWallet(mConfFactory.GetChainMode()),
            mBtc(mWallet, std::move(mConfFactory.conf.BitcoinValues()), "l15node-cli"),
            mCli("l15node-cli", false),
            mBtcd("bitcoind", false)

    {
        StartBitcoinNode();

        if(btc().GetChainHeight() < 50)
        {
            btc().CreateWallet("testwallet");
            btc().GenerateToOwnAddress("250");
        }
    }

    virtual ~TestcaseWrapper()
    {
        StopBitcoinNode();
        std::filesystem::remove_all(mConfFactory.GetBitcoinDataDir() + "/regtest");
    }

    void StartBitcoinNode()
    {
        StartNode(mConfFactory.GetChainMode(), mBtcd, conf().Subcommand(config::BITCOIND));
    }

    void StopBitcoinNode()
    {
        StopNode(mMode, mCli, conf().Subcommand(config::BITCOIN));
    }

    Config &conf()
    { return mConfFactory.conf; }

    api::WalletApi &wallet()
    { return mWallet; }

    api::ChainApi &btc()
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
        CKey sk = w->wallet().CreateNewKey();
        XOnlyPubKey pk(sk.GetPubKey());

        //create address from key pair
        string addr = w->wallet().Bech32mEncode(pk.begin(), pk.end());

        //send to the address
        string txid = w->btc().SendToAddress(addr, "1.001");

        auto prevout = w->btc().CheckOutput(txid, addr);
        uint32_t nout = std::get<0>(prevout).n;

        // create new wallet associated address
        string backaddr = w->btc().GetNewAddress();

        //spend first transaction to the last address

        bytevector backpk = w->wallet().Bech32Decode(backaddr);

        std::clog << "Payoff PK: " << HexStr(backpk) << std::endl;

        CMutableTransaction tx;

        CScript outpubkeyscript;
        outpubkeyscript << 1;
        outpubkeyscript << backpk;

        CTxOut out(ParseAmount("1"), outpubkeyscript);
        tx.vout.emplace_back(out);

        tx.vin.emplace_back(CTxIn(std::get<0>(prevout)));

        std::vector<CTxOut> prevtxouts = {std::get<1>(prevout)};

        bytevector sig = w->wallet().SignTaprootTx(sk, tx, 0, std::move(prevtxouts), {});

        std::clog << "Signature: " << HexStr(sig) << std::endl;

        tx.vin.front().scriptWitness.stack.emplace_back(sig);

        w->btc().SpendTx(CTransaction(tx));
    }

    SECTION("Taproot script path spending")
    {
        //get key pair Taproot
        CKey internal_sk = w->wallet().CreateNewKey();
        XOnlyPubKey internal_pk(internal_sk.GetPubKey());

        std::clog << "Internal PK: " << HexStr(internal_pk) << std::endl;

        //get key pair script
        CKey sk = w->wallet().CreateNewKey();
        XOnlyPubKey pk(sk.GetPubKey());
        bytevector pkbytes(pk.begin(), pk.end());


        //Create script merkle tree
        CScript script;
        script << pkbytes;
        script << OP_CHECKSIG;

        ScriptMerkleTree tap_tree (TreeBalanceType::WEIGHTED, {script});
        uint256 root = tap_tree.CalculateRoot();

        std::clog << "TapLeaf hash: " << HexStr(TapLeafHash(script)) << std::endl;

        std::clog << "TapTree root: " << HexStr(root) << std::endl;

        auto taptweak = internal_pk.CreateTapTweak(&root);
        XOnlyPubKey address_pk = taptweak->first;

        std::clog << "Taptweak parity flag: " << (taptweak->second ? 1 : 0) << std::endl;

        std::clog << "Taproot PK: " << HexStr(address_pk) << std::endl;

        string addr = w->wallet().Bech32mEncode(address_pk.begin(), address_pk.end());

        //send to the address
        string txid = w->btc().SendToAddress(addr, "1.001");

        auto prevout = w->btc().CheckOutput(txid, addr);


        // create new wallet associated address
        string backaddr = w->btc().GetNewAddress();

        //spend first transaction to the last address

        bytevector backpk = w->wallet().Bech32Decode(backaddr);

        std::clog << "Payoff PK: " << HexStr(backpk) << std::endl;

        CMutableTransaction tx;

        CScript outpubkeyscript;
        outpubkeyscript << 1;
        outpubkeyscript << backpk;

        CTxOut out(ParseAmount("1"), outpubkeyscript);
        tx.vout.emplace_back(out);

        tx.vin.emplace_back(CTxIn(std::get<0>(prevout)));

        std::vector<CTxOut> prevtxouts = {std::get<1>(prevout)};

        bytevector sig = w->wallet().SignTaprootTx(sk, tx, 0, std::move(prevtxouts), script);

        std::clog << "Signature: " << HexStr(sig) << std::endl;

        tx.vin.front().scriptWitness.stack.emplace_back(sig);
        tx.vin.front().scriptWitness.stack.emplace_back(bytevector(script.begin(), script.end()));



        auto scriptpath = tap_tree.CalculateScriptPath(script);

        bytevector controlblock = {static_cast<uint8_t>(0xc0 | (taptweak->second ? 1 : 0))};
        controlblock.reserve(1 + internal_pk.size() + scriptpath.size() * uint256::size());
        controlblock.insert(controlblock.end(), internal_pk.begin(), internal_pk.end());


        //std::copy(internal_pk.begin(), internal_pk.end(), cex::smartinserter(controlblock, controlblock.end()));

        //auto ins = cex::smartinserter(controlblock, controlblock.end());
        std::for_each(scriptpath.begin(), scriptpath.end(), [&](uint256 &branchhash)
            {
                controlblock.insert(controlblock.end(), branchhash.begin(), branchhash.end());
                //std::copy(branchhash.begin(), branchhash.end(), ins);
            });

        tx.vin.front().scriptWitness.stack.emplace_back(controlblock);


        //--------------------------------------------------------------------------------------------------------------------------------------
        // script verification
        //--------------------------------------------------------------------------------------------------------------------------------------
//        {
//
//            CScript scriptToVerify;
//            scriptToVerify << 1;
//            scriptToVerify << bytevector(address_pk.begin(), address_pk.end());
//
//            MutableTransactionSignatureChecker sigChecker(&tx, std::get<0>(prevout).n, ParseAmount("1"), MissingDataBehavior::ASSERT_FAIL); // TO CALC EXACT VALUE( prev output)
//            ScriptError error;
//            //unsigned flags = SCRIPT_VERIFY_NULLDUMMY | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_MINIMALDATA;
//            unsigned flags = SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_WITNESS ;
//            bool txres = VerifyScript(CScript(), scriptToVerify, &(tx.vin[0].scriptWitness), flags, sigChecker, &error);
//
//            CHECK(txres);
//
//        }




        w->btc().SpendTx(CTransaction(tx));

    }
}
