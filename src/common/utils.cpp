#include "utils.hpp"

#include "key.h"
#include "random.h"
#include "univalue.h"
#include "primitives/transaction.h"

#include "common_error.hpp"

#include <iostream>

namespace l15 {

const char* const Hrp<IBech32Coder::BTC, IBech32Coder::MAINNET>::value = "bc";
const char* const Hrp<IBech32Coder::BTC, IBech32Coder::TESTNET>::value = "tb";
const char* const Hrp<IBech32Coder::BTC, IBech32Coder::REGTEST>::value = "bcrt";
const char* const Hrp<IBech32Coder::L15, IBech32Coder::MAINNET>::value = "l15";
const char* const Hrp<IBech32Coder::L15, IBech32Coder::TESTNET>::value = "l15t";
const char* const Hrp<IBech32Coder::L15, IBech32Coder::REGTEST>::value = "l15rt";

inline bytevector ParsePubKey(const std::string &pubkeyhex)
{
    std::vector<uint8_t> pubkeybytes = ParseHex(pubkeyhex);
    CPubKey pubkey(pubkeybytes);
    if(!pubkey.IsFullyValid())
    {
        throw std::runtime_error(std::string("Pubkey is not valid: ") + pubkeyhex);
    }
    return pubkeybytes;
}


bytevector ScriptHash(const CScript &script)
{
    std::vector<uint8_t> scripthash;
    scripthash.resize(CSHA256::OUTPUT_SIZE);

    CSHA256().Write(script.data(), script.size()).Finalize(scripthash.data());

    return scripthash;
}

bytevector CreatePreimage()
{
    std::vector<uint8_t> random;
    random.resize(32);

    GetStrongRandBytes(Span(random.data(), random.size()));

    return random;
}

bytevector Hash160(const bytevector& preimage)
{

    bytevector hash160(CHash160::OUTPUT_SIZE);
    CHash160().Write(preimage).Finalize(hash160);
    return hash160;
}

CAmount GetOutputAmount(const std::string& txoutstr)
{
    UniValue txout;
    txout.read(txoutstr);

    const std::string &amountstr = find_value(txout, "value").getValStr();
    return ParseAmount(amountstr);
}

uint32_t GetCsvInBlocks(uint32_t blocks)
{

    if (blocks > CTxIn::SEQUENCE_LOCKTIME_MASK)
    {
        std::ostringstream buf;
        buf << "Relative lock time is too large: " << blocks;
        throw std::runtime_error(buf.str());
    }

    // CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG is set for CSV using median time

    return blocks;
}

CAmount ParseAmount(const std::string& amountstr)
{
    CAmount amount;
    if (!ParseFixedPoint(amountstr, 8, &amount)) {
        throw TransactionError(std::string("Error parsing amount: ") + amountstr);
    }
    return amount;
}

std::string FormatAmount(CAmount amount)
{
    std::ostringstream str_amount;
    str_amount << (amount / COIN);
    CAmount rem = amount % COIN;
    if (rem) str_amount << '.' << rem;
    return str_amount.str();
}

CAmount CalculateOutputAmount(CAmount input_amount, CAmount fee_rate, size_t size)
{
    CAmount fee = static_cast<int64_t>(size) * fee_rate / 1024;
    if ((fee + fee) >= input_amount) {
        std::ostringstream buf;
        buf << "Input amount too small (dust): " << FormatAmount(input_amount) << ", calculated fee: " << FormatAmount(fee);
        throw TransactionError(buf.str());
    }
    return input_amount - fee;
}

}
