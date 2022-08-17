#pragma once

#include <string>

#include "common.hpp"

namespace CLI {
class App;
}

namespace l15 {

  class ExecHelper;

  void StartNode(ChainMode mode, ExecHelper& node_exec, const CLI::App& options);
  void StopNode(ChainMode mode, ExecHelper& cli_exec, const CLI::App& options);

}