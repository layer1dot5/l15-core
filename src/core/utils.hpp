#pragma once

#include <string>
#include <vector>

#include "util/strencodings.h"
#include "crypto/sha256.h"
#include "script/script.h"
#include "uint256.h"
#include "amount.h"

#include "common.hpp"

namespace l15 {

inline CAmount ParseAmount(const std::string& amountstr)
{
    CAmount amount;
    if(!ParseFixedPoint(amountstr, 8, &amount))
    {
        throw std::runtime_error(std::string("Error parsing amount: ") + amountstr);
    }
    return amount;
}

bytevector ScriptHash(const CScript &script);
bytevector CreatePreimage();
bytevector Hash160(const bytevector& preimage);
CAmount GetOutputAmount(const std::string& txoutstr);
uint32_t GetCsvInBlocks(uint32_t blocks);

}
