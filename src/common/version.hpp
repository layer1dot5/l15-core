#pragma once

#include <string>

namespace l15 {

struct Version
{
    const static char *const core_version;
    const static char *const node_version;
    const static char *const secp256k1_version;

    static std::string MakeFullVersion() {
        return std::string("Core: ") + core_version +
                "\nNode: " + node_version +
                "\nSecp256k1: " + secp256k1_version;
    }

};

}
