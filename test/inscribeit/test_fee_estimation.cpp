
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
    l15::inscribeit::FeeCalculator<l15::inscribeit::SwapInscriptionBuilder> feeCalculator("regtest", sFeeRate, sFeeRate);

    auto feeRate = l15::ParseAmount(sFeeRate);

    CAmount fee, sumFee = 0;
    REQUIRE_NOTHROW(fee = feeCalculator.getFundsCommit(feeRate));
    CHECK(fee == 162);
    sumFee += fee;
/*
    REQUIRE_NOTHROW(fee = feeCalculator.getFee(feeRate, l15::inscribeit::TransactionKind::OrdinalCommit));
    CHECK(fee == 162);
    sumFee += fee;

    REQUIRE_NOTHROW(fee = feeCalculator.getFee(feeRate, l15::inscribeit::TransactionKind::OrdinalTransfer));
    CHECK(fee == 162);
    sumFee += fee;

    REQUIRE_NOTHROW(fee = feeCalculator.getFee(feeRate, l15::inscribeit::TransactionKind::OrdinalSwap));
    CHECK(fee == 544);
    sumFee += fee;
    std::cout << sumFee << std::endl;*/
}
