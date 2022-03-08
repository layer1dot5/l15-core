#pragma once

#include "CLI11.hpp"

namespace l15 {

class Config {
    CLI::App mApp;
public:
    explicit Config();
    ~Config() = default;

    void ProcessConfig(std::vector<std::string>& args)
    {
        try
        {
            mApp.parse(args);
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

    void ProcessConfig(std::istream& stream);

};

}