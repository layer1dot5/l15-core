#pragma once

#include "CLI11.hpp"
#include "common.hpp"

namespace l15 {

namespace config {

extern const char* const L15NODE;
extern const char* const L15CLIENT;
extern const char* const BITCOIN;
extern const char* const BITCOIND;

namespace command {

} // namespace l15::config::command

namespace option {

extern const char* const CONF;
extern const char* const RPCHOST;
extern const char* const RPCPORT;
extern const char* const RPCUSER;
extern const char* const RPCPASS;
extern const char* const DATADIR;

} // namespace l15::config::option

} // namespace l15::config

class Config {
private:
    CLI::App mApp;

public:
    explicit Config();
    ~Config() = default;

    void ProcessConfig(const std::vector<std::string>& args)
    {
        try
        {
            mApp.parse(stringvector(args));
        }
        catch(const CLI::ParseError &e)
        {
            mApp.exit(e);
        }
    }

    void ProcessConfig(int argc, const char* const argv[])
    {
        try
        {
            mApp.parse(argc, argv);
        }
        catch(const CLI::ParseError &e)
        {
            mApp.exit(e);
        }
    }

    const CLI::App& Subcommand(const std::string& name) const
    {
        return *mApp.get_subcommand(name);
    }

    stringvector ChainValues(const char* const chain) const
    {
        auto& btccli = Subcommand(chain);

        stringvector values;

        for(const auto opt: btccli.get_options([](const CLI::Option* o){ return o&& !o->check_name("--help"); }))
        {
            values.emplace_back(opt->get_name() + "=" + opt->template as<std::string>());
        }

        return values;

    }

};

} // namespace l15
