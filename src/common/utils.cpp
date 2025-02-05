#include "utils.hpp"

#include "key.h"
#include "random.h"
#include "consensus.h"
#include "feerate.h"
#include "transaction.h"
#include "policy.h"

#include "common_error.hpp"
#include "bech32.hpp"

#include "nlohmann/json.hpp"

#include <string>


namespace l15 {

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

template<typename T>
CAmount CalculateTxFee(CAmount fee_rate, const T& tx)
{
    size_t tx_size = GetSerializeSize(TX_NO_WITNESS(tx));
    size_t tx_wit_size = GetSerializeSize(TX_WITH_WITNESS(tx));
    size_t vsize = (tx_size * (WITNESS_SCALE_FACTOR - 1) + tx_wit_size + 3) / WITNESS_SCALE_FACTOR;

//    std::clog << ">>>>>>>>>>>>>>>> vsize: " << vsize << std::endl;

    return CFeeRate(fee_rate).GetFee(vsize);
}

template CAmount CalculateTxFee<CMutableTransaction>(CAmount fee_rate, const CMutableTransaction& );
template CAmount CalculateTxFee<CTransaction>(CAmount fee_rate, const CTransaction& );

[[deprecated]]
CAmount CalculateOutputAmount(CAmount input_amount, CAmount fee_rate, const CMutableTransaction& tx)
{
    auto fee = CalculateTxFee(fee_rate, tx);
    // if ((fee + Dust(DUST_RELAY_TX_FEE)) >= input_amount) {
    //     std::ostringstream buf;
    //     buf << "Input amount too small (dust): " << FormatAmount(input_amount) << ", calculated fee: " << FormatAmount(fee);
    //     throw TransactionError(buf.str());
    // }
    return input_amount - fee;
}


}
