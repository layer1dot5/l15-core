#include <filesystem>
#include <iostream>

#include "config.hpp"

namespace l15 {

namespace config {

    const char * const L15NODE = "l15node";
    const char * const L15CLIENT = "l15client";
    const char * const BITCOIN = "bitcoin";
    const char * const BITCOIND = "bitcoind";

namespace option {

const char * const CONF = "--conf";
const char * const RPCHOST = "--rpcconnect";
const char * const RPCPORT = "--rpcport";
const char * const RPCUSER = "--rpcuser";
const char * const RPCPASS = "--rpcpassword";
const char * const DATADIR = "--datadir";
const char * const CHAINMODE = "--mode";

namespace mode {
    const char * const MAINNET = "mainnet";
    const char * const TESTNET = "testnet";
    const char * const REGTEST = "regtest";
}

}

}

namespace {

std::string make_absolute_path(const std::string& v) {
    std::filesystem::path p(v);
    if(p.is_relative())
        return (std::filesystem::current_path() / p).string();
    else
        return v;
}

}

using namespace ::l15::config;

Config::Config():mApp(PACKAGE_NAME,PACKAGE_NAME)
{
    mApp.set_config(option::CONF, "l15.conf", "Read the configuration file");
    mApp.set_version_flag("--version,-v", PACKAGE_STRING);
    mApp.set_help_flag("--help,-h");

    mApp.add_option(option::CHAINMODE, "Mode to operate: mainnet, testnet, regtest")->check([](const std::string& s){
            if (s != option::mode::MAINNET && s != option::mode::TESTNET && s != option::mode::REGTEST) throw CLI::ValidationError("Unknown chain mode: " + s);
            return std::string();
        })->default_str(option::mode::MAINNET);

    //-------------------------------------------------------------------------
    // [l15node]
    {
        auto l15node = mApp.add_subcommand(L15NODE);
        l15node->configurable();
        l15node->group("Config File Sections");
        l15node->add_option(option::DATADIR, "Path to store files for L15 node daemon")->configurable(true);
                //->default_str(".l15")
                //->transform(make_absolute_path);

        l15node->add_option(option::CONF, "L15 node configuration file. Relative paths will be prefixed by datadir path")->configurable(true);
                //->default_str("l15.conf")
                //->transform(make_absolute_path);
    }

    //-------------------------------------------------------------------------
    // [l15client]
    {
        auto l15client = mApp.add_subcommand(L15CLIENT);
        l15client->group("Config File Sections");
        l15client->add_option(option::RPCHOST, "L15 node RPC host");
                //->default_str("127.0.0.1")->capture_default_str();
        l15client->add_option(option::RPCPORT, "L15 node RPC port");
                //->default_str("18332")->capture_default_str();
        l15client->add_option(option::RPCUSER, "L15 node RPC user");
                //->default_str("rpcuser")->capture_default_str();
        l15client->add_option(option::RPCPASS, "L15 node RPC password");
    }


//    //-------------------------------------------------------------------------
//    // [bitcoind]
//    {
//        auto bitcoind = mApp.add_subcommand(BITCOIND);
//        bitcoind->group("Config File Sections");
//        /*auto datadir = */bitcoind->add_option(option::DATADIR, "Path to store files for bitcoin daemon");
//                //->default_str(".bitcoin")
//                //->transform(make_absolute_path);
//
//        bitcoind->add_option(option::CONF, "L15 node configuration file. Relative paths will be prefixed by datadir path")
//                //->default_str("bitcoin.conf")
//                ->transform(make_absolute_path);
//    }
//
//    //-------------------------------------------------------------------------
//    // [bitcoin]
//    {
//        auto bitcoin = mApp.add_subcommand(BITCOIN);
//        bitcoin->group("Config File Sections");
//        bitcoin->add_option(option::RPCHOST, "Bitcoin RPC host")->default_str("127.0.0.1")->capture_default_str();
//        bitcoin->add_option(option::RPCPORT, "Bitcoin RPC port")->default_str("18332")->capture_default_str();
//        bitcoin->add_option(option::RPCUSER, "Bitcoin RPC user")->default_str("rpcuser")->capture_default_str();
//        bitcoin->add_option(option::RPCPASS, "Bitcoin RPC password");
//    }


    auto print = mApp.add_subcommand("print");
    print->configurable(false);
    print->callback([&](){
        std::cout << "Current configuration:" << std::endl;

        std::cout << mApp.config_to_str(true) << std::endl;

    });

}

}