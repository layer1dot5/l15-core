
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"

#include "core_io.h"
#include "policy/policy.h"
#include "util/translation.h"

#include "config.hpp"
#include "nodehelper.hpp"
#include "fee_calculator.hpp"

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

const std::string feeRate = "0.000015";

TEST_CASE("FeeCalculatorInitialization")
{

    l15::inscribeit::FeeCalculator feeCalculator;

    CAmount fee, sumFee = 0;
    REQUIRE_NOTHROW(fee = feeCalculator.getFee(feeRate, l15::inscribeit::TransactionKind::FundsCommit));
    CHECK(fee == 162);
    sumFee += fee;

    REQUIRE_NOTHROW(fee = feeCalculator.getFee(feeRate, l15::inscribeit::TransactionKind::OrdinalCommit));
    CHECK(fee == 162);
    sumFee += fee;

    REQUIRE_NOTHROW(fee = feeCalculator.getFee(feeRate, l15::inscribeit::TransactionKind::OrdinalTransfer));
    CHECK(fee == 162);
    sumFee += fee;

    REQUIRE_NOTHROW(fee = feeCalculator.getFee(feeRate, l15::inscribeit::TransactionKind::OrdinalSwap));
    CHECK(fee == 544);
    sumFee += fee;
    std::cout << sumFee << std::endl;
}

TEST_CASE("FeeCalculatorNotImplemented")
{
    l15::inscribeit::FeeCalculator feeCalculator;
    REQUIRE_THROWS_AS(feeCalculator.getFee(feeRate, l15::inscribeit::TransactionKind::NotImplemented), l15::TransactionError);
}
