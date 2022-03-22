#include <thread>


#include "nodehelper.hpp"
#include "exechelper.hpp"
#include "config.hpp"

namespace l15 {

using namespace api;

void StartNode(ChainMode mode, const std::string &path, const CLI::App& options)
{
    ExecHelper node_exec(path.c_str(), false);
    node_exec.Arguments().emplace_back("-daemon");

    for(const auto opt: options.get_options([](const CLI::Option* o){ return o && !o->check_name("--help"); }))
    {
        node_exec.Arguments().emplace_back(opt->get_name() + "=" + opt->as<std::string>());
    }
    if(mode == ChainMode::MODE_REGTEST) node_exec.Arguments().emplace_back("-regtest");
    else if(mode == ChainMode::MODE_TESTNET) node_exec.Arguments().emplace_back("-testnet");

    node_exec.Run();

    std::this_thread::sleep_for(std::chrono::seconds(5));
}

void StopNode(ChainMode mode, const std::string &path, const CLI::App& options)
{
    ExecHelper cli_exec(path.c_str(), false);

    for(const auto opt: options.get_options([](const CLI::Option* o){ return o; }))
    {
        cli_exec.Arguments().emplace_back(opt->get_name() + "=" + opt->as<std::string>());
    }
    if(mode == ChainMode::MODE_REGTEST) cli_exec.Arguments().emplace_back("-regtest");
    else if(mode == ChainMode::MODE_TESTNET) cli_exec.Arguments().emplace_back("-testnet");

    cli_exec.Arguments().emplace_back("stop");

    cli_exec.Run();

    std::this_thread::sleep_for(std::chrono::seconds(5));
}
}
