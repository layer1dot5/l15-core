#pragma once

#include <string>

#include "common_api.hpp"

namespace CLI {
class App;
}

namespace l15 {

  class ExecHelper;

  void StartNode(api::ChainMode mode, ExecHelper& node_exec, const CLI::App& options);
  void StopNode(api::ChainMode mode, ExecHelper& cli_exec, const CLI::App& options);

}