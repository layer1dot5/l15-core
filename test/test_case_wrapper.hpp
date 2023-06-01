#pragma once

#include "common.hpp"
#include "chain_api.hpp"
#include "config.hpp"


namespace l15 {

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
        if (!datadir_opt->empty())
            return datadir_opt->as<std::string>();
        else
            return std::string();
    }
};

struct TestcaseWrapper
{
    TestConfigFactory mConfFactory;
    std::string mMode;
    core::ChainApi mBtc;
    ExecHelper mCli;
    ExecHelper mBtcd;
    std::unique_ptr<IBech32Coder> mBech;

    explicit TestcaseWrapper(const std::string& configpath, const std::string& clipath) :
            mConfFactory(configpath),
            mMode(mConfFactory.conf[config::option::CHAINMODE].as<std::string>()),
            mBtc(std::move(mConfFactory.conf.ChainValues(config::BITCOIN)), clipath),
            mCli(clipath, false),
            mBtcd("bitcoind", false)
    {
        if (mMode == "regtest") {
            mBech.reset(new Bech32Coder<IBech32Coder::BTC, IBech32Coder::REGTEST>());
        }
        else if (mMode == "testnet") {
            mBech.reset(new Bech32Coder<IBech32Coder::BTC, IBech32Coder::TESTNET>());
        }
        else {
            throw std::runtime_error("Wrong chain mode");
        }

        bool is_connected = true;
        try {
            btc().CheckConnection();
        }
        catch (...) {
            is_connected = false;
        }

        if (!is_connected && mConfFactory.conf[config::option::CHAINMODE].as<std::string>() == "regtest") {
            StartRegtestBitcoinNode();
        }

        try {
            btc().GetWalletInfo();
        }
        catch (...) {
            btc().CreateWallet("testwallet");
        }
        if (mConfFactory.conf[config::option::CHAINMODE].as<std::string>() == "regtest") {
            btc().GenerateToAddress(btc().GetNewAddress(), "151");
        }
        else if (mConfFactory.conf[config::option::CHAINMODE].as<std::string>() == "testnet") {
            btc().WalletPassPhrase("********", "30");
        }
    }

    virtual ~TestcaseWrapper()
    {
        if (mConfFactory.conf[config::option::CHAINMODE].as<std::string>() == "regtest") {
            StopRegtestBitcoinNode();
            std::filesystem::remove_all(mConfFactory.GetBitcoinDataDir() + "/regtest");
        }
    }

    void StartRegtestBitcoinNode()
    {
        StartNode(ChainMode::MODE_REGTEST, mBtcd, conf().Subcommand(config::BITCOIND));
    }

    void StopRegtestBitcoinNode()
    {
        StopNode(ChainMode::MODE_REGTEST, mCli, conf().Subcommand(config::BITCOIN));
    }

    Config& conf()
    { return mConfFactory.conf; }

    core::ChainApi& btc()
    { return mBtc; }

    IBech32Coder& bech32() const
    { return *mBech; }

    void ResetRegtestMemPool()
    {
        StartRegtestBitcoinNode();

        std::filesystem::remove(mConfFactory.GetBitcoinDataDir() + "/regtest/mempool.dat");

        StopRegtestBitcoinNode();
    }
};

}