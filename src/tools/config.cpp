#include "config.hpp"

namespace l15 {

Config::Config():mApp(PACKAGE_NAME,PACKAGE_NAME)
{
    mApp.set_config("--config", "l15.conf", "Read the configuration file");
    mApp.set_version_flag("--version,-v", PACKAGE_VERSION);
    mApp.set_help_flag("--help,-h");
}

}