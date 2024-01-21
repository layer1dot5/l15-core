#pragma once

#include <algorithm>

#include "feerate.h"

#include "utils.hpp"

namespace l15 {

template<typename T>
CAmount CheckMiningFee(CAmount funds_in, const T tx, CAmount feerate)
{
    CAmount funds_out = 0;
    funds_out = std::accumulate(tx.vout.begin(), tx.vout.end(), funds_out, [](CAmount prev, const auto& out) { return prev + out.nValue;});
    CAmount fee = CalculateTxFee(feerate, tx);

    return funds_in - funds_out - fee;
}

}