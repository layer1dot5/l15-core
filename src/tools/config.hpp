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

}

namespace option {

extern const char* const CONF;
extern const char* const RPCHOST;
extern const char* const RPCPORT;
extern const char* const RPCUSER;
extern const char* const RPCPASS;
extern const char* const DATADIR;

}

}

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

    stringvector BitcoinValues() const;

};

}