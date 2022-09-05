#pragma once

#include "config.hpp"
#include "nodehelper.hpp"
#include "chain_api.hpp"
#include "wallet_api.hpp"
#include "exechelper.hpp"
#include "onchain_service.hpp"

extern std::string configpath;

namespace l15 {

struct ConfigFactory
{
    Config conf;

    explicit ConfigFactory(const std::string &confpath)
    {
        std::clog << "Config: " << confpath << std::endl;
        conf.ProcessConfig({"--conf=" + confpath});
        std::clog << "Config has been processed" << std::endl;
    }

    std::string GetDataDir() const
    {
        auto datadir_opt = conf.Subcommand(config::L15NODE).get_option(config::option::DATADIR);
        if (!datadir_opt->empty())
            return datadir_opt->as<std::string>();
        else
            return std::string();
    }
};

struct NodeWrapper
{
    ConfigFactory mConfFactory;
    core::WalletApi wallet;
    chain_service::OnChainService node_service;

    explicit NodeWrapper() :
            mConfFactory(configpath),
            wallet(),
            node_service(
                    std::make_unique<core::ChainApi>(Bech32Coder<IBech32Coder::L15, IBech32Coder::REGTEST>(), std::move(mConfFactory.conf.ChainValues(config::L15NODE)),
                     "l15node-cli"))
    {
        startNode();
    }

    ~NodeWrapper()
    {
        ExecHelper cli("l15node-cli", false);
        StopNode(ChainMode::MODE_REGTEST, cli, conf().Subcommand(config::L15CLIENT));
        std::filesystem::remove_all(mConfFactory.GetDataDir() + "/regtest");
    }

    void startNode()
    {
        ExecHelper node("l15noded", false);
        StartNode(ChainMode::MODE_REGTEST, node, conf().Subcommand(config::L15NODE));
    }

    Config &conf()
    { return mConfFactory.conf; }
};

}
