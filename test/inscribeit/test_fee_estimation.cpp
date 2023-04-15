
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"

#include "core_io.h"
#include "policy/policy.h"
#include "util/translation.h"

#include "config.hpp"
#include "nodehelper.hpp"
#include "fee_calculator.hpp"
#include "swap_inscription.hpp"
#include "utils.hpp"

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

const std::string sFeeRate = "0.000015";

TEST_CASE("FeeCalculatorCalculation")
{
    auto feeRate = l15::ParseAmount(sFeeRate);
/*
    CAmount fee, sumFee = 0;
    REQUIRE_NOTHROW(fee = feeCalculator.getFundsCommit(feeRate));
    CHECK(fee == 225);
    sumFee += fee;

    REQUIRE_NOTHROW(fee = feeCalculator.getOrdinalCommit(feeRate));
    CHECK(fee == 162);
    sumFee += fee;

    REQUIRE_NOTHROW(fee = feeCalculator.getOrdinalTransfer(feeRate));
    CHECK(fee == 162);
    sumFee += fee;

    REQUIRE_NOTHROW(fee = feeCalculator.getOrdinalSwap(feeRate));
    CHECK(fee == 520);
    sumFee += fee;
    std::cout << sumFee << std::endl;
    */
}

