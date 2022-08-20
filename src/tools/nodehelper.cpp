#include <thread>


#include "nodehelper.hpp"
#include "exechelper.hpp"
#include "config.hpp"

namespace l15 {

void StartNode(ChainMode mode, ExecHelper& node_exec, const CLI::App& options)
{
    node_exec.Arguments().clear();
    node_exec.Arguments().emplace_back("-daemon");

    for(const auto opt: options.get_options([](const CLI::Option* o){ return o && !o->check_name("--help"); }))
    {
        std::clog << opt->get_name() << " == " << opt->as<std::string>() << std::endl;
        node_exec.Arguments().emplace_back(opt->get_name() + "=" + opt->as<std::string>());
    }
    if(mode == ChainMode::MODE_REGTEST) node_exec.Arguments().emplace_back("-regtest");
    else if(mode == ChainMode::MODE_TESTNET) node_exec.Arguments().emplace_back("-testnet");

    node_exec.Run();

    std::this_thread::sleep_for(std::chrono::seconds(5));
}

void StopNode(ChainMode mode, ExecHelper& cli_exec, const CLI::App& options)
{
    cli_exec.Arguments().clear();

    for(const auto opt: options.get_options([](const CLI::Option* o){ return o&& !o->check_name("--help"); }))
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
