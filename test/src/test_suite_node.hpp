#pragma once

#include "tools/config.hpp"
#include "tools/nodehelper.hpp"
#include "core/chain_api.hpp"
#include "core/wallet_api.hpp"
#include "core/exechelper.hpp"

struct TestConfigFactory
{
    l15::Config conf;

    explicit TestConfigFactory(const std::string &confpath)
    {
        conf.ProcessConfig({"--conf=" + confpath});
    }

    l15::api::ChainMode GetChainMode() const
    {
        return l15::api::ChainMode::MODE_REGTEST;
    }

    std::string GetBitcoinDataDir() const
    {
        auto datadir_opt = conf.Subcommand(l15::config::BITCOIND).get_option(l15::config::option::DATADIR);
        if(!datadir_opt->empty())
            return datadir_opt->as<std::string>();
        else
            return std::string();
    }
};

struct NodeWrapper
{
    const std::string m_CONFIG_API;
    const std::string m_CONFIG_DAEMON;
    TestConfigFactory mConfFactory;
    l15::api::ChainMode mMode;
    l15::api::WalletApi mWallet;
    l15::api::ChainApi mBtc;
    l15::ExecHelper mCli;
    l15::ExecHelper mBtcd;

    NodeWrapper(const std::string& configpath, const char* cli_path, const char* daemon_path, const char* config_api, const char* config_daemon) :
            m_CONFIG_API(config_api),
            m_CONFIG_DAEMON(config_daemon),
            mConfFactory(configpath),
            mMode(mConfFactory.GetChainMode()),
            mWallet(mConfFactory.GetChainMode()),
            mBtc(mWallet, std::move(mConfFactory.conf.BitcoinValues()), cli_path),
            mCli(cli_path, false),
            mBtcd(daemon_path, false)
    {
    }

    void start_node()
    {
        l15::StartNode(mConfFactory.GetChainMode(), mBtcd, conf().Subcommand(m_CONFIG_DAEMON));
    }

    void stop_node()
    {
        l15::StopNode(mMode, mCli, conf().Subcommand(m_CONFIG_API));
    }

    l15::Config &conf()
    { return mConfFactory.conf; }

    l15::api::WalletApi &wallet()
    { return mWallet; }

    l15::api::ChainApi &btc()
    { return mBtc; }

};