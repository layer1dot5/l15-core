#include "utils.hpp"

#include "key.h"
#include "random.h"
#include "univalue.h"
#include "primitives/transaction.h"
#include "consensus.h"

#include "common_error.hpp"

#include <iostream>
#include <string>


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
    if (!amount) return "0";
    static const size_t digits = std::to_string(COIN).length() - 1;
    std::string str_amount =  std::to_string(amount);
    std::ostringstream buf;
    if (amount < COIN) {
        buf << "0.";
        for (size_t i = 0; i < (digits - str_amount.length()); ++i) buf << '0';
        size_t print_digits = str_amount.length();
        for (;!(amount % 10);amount /= 10) {
            --print_digits;
        }
        buf << str_amount.substr(0, print_digits);
        return buf.str();
    }
    else {
        buf << str_amount.substr(0, str_amount.length() - digits) << '.' << str_amount.substr(str_amount.length() - digits);
    }

    std::string res = buf.str();

    size_t cut_zeroes = 0;
    for (auto i = res.rbegin(); i != res.rend() && *i == '0'; ++i, ++cut_zeroes) ;
    if (res[res.length() - cut_zeroes - 1] == '.') ++cut_zeroes;

    return res.substr(0, res.length() - cut_zeroes);
}

CAmount CalculateTxFee(CAmount fee_rate, const CMutableTransaction& tx)
{
    size_t tx_size = GetSerializeSize(tx, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
    size_t tx_wit_size = GetSerializeSize(tx, PROTOCOL_VERSION);
    size_t vsize = (tx_size * (WITNESS_SCALE_FACTOR - 1) + tx_wit_size + 3) / WITNESS_SCALE_FACTOR;

//    std::clog << ">>>>>>>>>>>>>>>> vsize: " << vsize << std::endl;

    return static_cast<int64_t>(vsize) * fee_rate / 1000;
}

CAmount CalculateOutputAmount(CAmount input_amount, CAmount fee_rate, const CMutableTransaction& tx)
{
    auto fee = CalculateTxFee(fee_rate, tx);
    if ((fee + fee) >= input_amount) {
        std::ostringstream buf;
        buf << "Input amount too small (dust): " << FormatAmount(input_amount) << ", calculated fee: " << FormatAmount(fee);
        throw TransactionError(buf.str());
    }
    return input_amount - fee;
}

}
