#pragma once

#include <string>

#include "common.hpp"

namespace CLI {
class App;
}

namespace l15 {

  enum class NodeChainMode {MODE_MAINNET, MODE_TESTNET, MODE_REGTEST};

  class ExecHelper;

  void StartNode(NodeChainMode mode, ExecHelper& node_exec, const CLI::App& options);
  void StopNode(NodeChainMode mode, ExecHelper& cli_exec, const CLI::App& options);

}