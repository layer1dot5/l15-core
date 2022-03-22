#include <filesystem>
#include <iostream>

#include "config.hpp"

namespace l15 {

namespace config {

    const char * const L15NODE = "l15node";
    const char * const L15CLIENT = "l15client";
    const char * const BITCOIN = "bitcoin";

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

using namespace ::l15::config;

Config::Config():mApp(PACKAGE_NAME,PACKAGE_NAME)
{
    mApp.set_config(option::CONF, "l15.conf", "Read the configuration file");
    mApp.set_version_flag("--version,-v", PACKAGE_STRING);
    mApp.set_help_flag("--help,-h");

    mApp.add_option(option::CHAINMODE, "Mode to operate: mainnet, testnet, regtest")->check([](const std::string& s){
            if (s != option::mode::MAINNET && s != option::mode::TESTNET && s != option::mode::REGTEST) throw CLI::ValidationError("Unknown chain mode: " + s);
            return s;
        })->default_str(option::mode::MAINNET);

    auto l15node = mApp.add_subcommand(L15NODE);
    l15node->group("Config File Sections");
    /*auto datadir = */l15node->add_option(option::DATADIR, "Path to store files for L15 node daemon")
//        ->default_str(".l15")
//        ->capture_default_str()
        ->transform([](const std::string& v)
        {
            std::clog << "datadir: " << v << std::endl;

            std::filesystem::path p(v);
            if(p.is_relative())
                return (std::filesystem::current_path() / p).string();
            else
                return v;
        });
    l15node->add_option(option::CONF, "L15 node configuration file. Relative paths will be prefixed by datadir path")
        ->default_str("l15.conf")
//        ->capture_default_str()
        ->transform([&](const std::string& v)
        {
//            std::filesystem::path p(v);
//            if(p.is_relative())
//                return (std::filesystem::path(datadir->as<std::string>()) / p).string();
//            else
                return v;
        });

    auto l15client = mApp.add_subcommand(L15CLIENT);
    l15client->group("Config File Sections");
    l15client->add_option(option::RPCHOST, "Node RPC host")->default_str("127.0.0.1")->capture_default_str();
    l15client->add_option(option::RPCPORT, "Node RPC port")->default_str("18332")->capture_default_str();
    l15client->add_option(option::RPCUSER, "Node RPC user")->default_str("rpcuser")->capture_default_str();
    l15client->add_option(option::RPCPASS, "Node RPC password");

    auto print = mApp.add_subcommand("print");
    print->callback([&](){
        std::cout << "Current configuration:" << std::endl;

        std::cout << mApp.config_to_str(true) << std::endl;

    });

}

}