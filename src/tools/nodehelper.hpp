#pragma once

#include <string>

#include "common_api.hpp"

namespace CLI {
class App;
}

namespace l15 {

  void StartNode(api::ChainMode mode, const std::string& path, const CLI::App& options);
  void StopNode(api::ChainMode mode, const std::string& cli_path, const CLI::App& options);

}