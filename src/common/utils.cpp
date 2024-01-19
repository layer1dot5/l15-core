#include "utils.hpp"

#include "key.h"
#include "random.h"
#include "univalue.h"
#include "primitives/transaction.h"
#include "consensus.h"
#include "feerate.h"

#include "common_error.hpp"
#include "policy.h"

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

    return CFeeRate(fee_rate).GetFee(vsize);
}

CAmount CalculateOutputAmount(CAmount input_amount, CAmount fee_rate, const CMutableTransaction& tx)
{
    auto fee = CalculateTxFee(fee_rate, tx);
    if ((fee + Dust(DUST_RELAY_TX_FEE)) >= input_amount) {
        std::ostringstream buf;
        buf << "Input amount too small (dust): " << FormatAmount(input_amount) << ", calculated fee: " << FormatAmount(fee);
        throw TransactionError(buf.str());
    }
    return input_amount - fee;
}

template <typename T>
void LogTx(const T& tx)
{
    std::clog << "Transaction " << tx.GetHash().GetHex() << " {\n"
              << "\tnLockTime: " << tx.nLockTime << "\n"
              << "\tvin {\n";
    bool first_in = true;
    for(const auto& in: tx.vin)
    {
        if(first_in) first_in = false;
        else std::clog << "\t\t------------------------------------------------\n";

        std::clog << "\t\t" << in.prevout.hash.GetHex() << " : "
                  << in.prevout.n << "\n"
                  << "\t\tWitness {\n";

        for(const auto& wel: in.scriptWitness.stack)
        {
            std::clog << "\t\t\t{" << HexStr(wel) << "}\n";
        }
        std::clog << "\t\t}\n";
    }
    std::clog << "\t}\n";

    std::clog << "\tvout {\n";
    bool first_out = true;
    for(const auto& out: tx.vout)
    {
        if(first_out) first_out = false;
        else std::clog << "\t\t------------------------------------------------\n";

        std::clog << "\t\tAmount: " << out.nValue << "\n";

        bytevector wp;
        int wver;
        if(out.scriptPubKey.IsWitnessProgram(wver, wp))
        {
            if(wver == 0 && wp.size() == 20) std::clog << "\t\tPubKeyHash Witness program: "  << HexStr(wp) << "\n";
            else if (wver == 0 && wp.size() == 32) std::clog << "\t\tScriptHash Witness program: " << HexStr(wp) << "\n";
            else std::clog << "\t\tWitness program v" << wver << ": " << HexStr(wp) << "\n";
        } else
        {
            std::clog << "\t\tScriptPubKey: "<< HexStr(out.scriptPubKey) << "\n";
        }

    }
    std::clog << "\t}\n}" << std::endl;
}

template void LogTx<CTransaction>(const CTransaction& );
template void LogTx<CMutableTransaction>(const CMutableTransaction& );


}
