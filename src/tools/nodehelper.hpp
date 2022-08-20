#pragma once

#include <string>

#include "common.hpp"

namespace CLI {
class App;
}

namespace l15 {

  enum class ChainMode {MODE_MAINNET, MODE_TESTNET, MODE_REGTEST};

  class ExecHelper;

  void StartNode(ChainMode mode, ExecHelper& node_exec, const CLI::App& options);
  void StopNode(ChainMode mode, ExecHelper& cli_exec, const CLI::App& options);

}