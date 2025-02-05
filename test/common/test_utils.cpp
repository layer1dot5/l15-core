#include <iostream>
#include <filesystem>
#include <cstring>

#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"

#include "util/translation.h"
#include "transaction.h"

#include "utils.hpp"
#include "transaction.hpp"

using namespace l15;

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

TEST_CASE("logtx")
{
    CMutableTransaction tx;

    tx.vin.emplace_back(Txid(), 0);
    tx.vout.emplace_back(546, CScript() << 1 << unhex<bytevector>("f4bd18cdaa7c9212143b9ff0547e3b1f81379219dcbbe3cbb9743688e0a4daa4"));

    LogTx(TESTNET, tx); std::clog << std::endl;
    LogTx(TESTNET, tx, std::clog);
    std::clog << LogTx<std::string>(TESTNET, tx) << std::endl;
}
