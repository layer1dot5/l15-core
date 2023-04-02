#pragma once

#include <string>
#include <vector>

#include "bech32.h"
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

inline std::string FormatAmount(CAmount amount)
{
    std::ostringstream str_amount;
    str_amount << (amount / COIN);
    CAmount rem = amount % COIN;
    if (rem) str_amount << '.' << rem;
    return str_amount.str();
}

inline CAmount CalculateOutputAmount(CAmount input_amount, CAmount fee_rate, size_t size)
{
    return input_amount - static_cast<int64_t>(size) * fee_rate / 1024;
}


bytevector ScriptHash(const CScript &script);
bytevector CreatePreimage();
bytevector Hash160(const bytevector& preimage);
CAmount GetOutputAmount(const std::string& txoutstr);
uint32_t GetCsvInBlocks(uint32_t blocks);

class IBech32Coder {

public:
    enum ChainType {BTC, L15};
    enum ChainMode {MAINNET, TESTNET, REGTEST};

    virtual ~IBech32Coder() = default;
    virtual std::string Encode(const xonly_pubkey& pk) const = 0;
    virtual xonly_pubkey Decode(const std::string& address) const = 0;
};

template <IBech32Coder::ChainType C, IBech32Coder::ChainMode M> struct Hrp;
template <> struct Hrp<IBech32Coder::BTC, IBech32Coder::MAINNET> { const static char* const value; };
template <> struct Hrp<IBech32Coder::BTC, IBech32Coder::TESTNET> { const static char* const value; };
template <> struct Hrp<IBech32Coder::BTC, IBech32Coder::REGTEST> { const static char* const value; };
template <> struct Hrp<IBech32Coder::L15, IBech32Coder::MAINNET> { const static char* const value; };
template <> struct Hrp<IBech32Coder::L15, IBech32Coder::TESTNET> { const static char* const value; };
template <> struct Hrp<IBech32Coder::L15, IBech32Coder::REGTEST> { const static char* const value; };


template <IBech32Coder::ChainType C, IBech32Coder::ChainMode M> class Bech32Coder: public IBech32Coder
{
public:
    typedef Hrp<C,M> hrp;

    ~Bech32Coder() override = default;
    std::string Encode(const xonly_pubkey& pk) const override {
        std::vector<unsigned char> bech32buf = {1};
        bech32buf.reserve(1 + ((pk.end() - pk.begin()) * 8 + 4) / 5);
        ConvertBits<8, 5, true>([&](unsigned char c) { bech32buf.push_back(c); }, pk.begin(), pk.end());
        return bech32::Encode(bech32::Encoding::BECH32M, hrp::value, bech32buf);

    }
    xonly_pubkey Decode(const std::string& address) const override {
        bech32::DecodeResult bech_result = bech32::Decode(address);
        if(bech_result.hrp != hrp::value)
        {
            throw std::runtime_error(std::string("Address prefix should be ") + hrp::value + ". Address: " + address);
        }
        if(bech_result.data.size() < 1)
        {
            throw std::runtime_error(std::string("Wrong bech32 data (no data decoded): ") + address);
        }
        if(bech_result.data[0] == 0 && bech_result.encoding != bech32::Encoding::BECH32)
        {
            throw std::runtime_error("Version 0 witness address must use Bech32 checksum");
        }
        if(bech_result.data[0] != 0 && bech_result.encoding != bech32::Encoding::BECH32M)
        {
            throw std::runtime_error("Version 1+ witness address must use Bech32m checksum");
        }

        xonly_pubkey data;
        auto I = data.begin();
        if(!ConvertBits<5, 8, false>([&](unsigned char c) { *I++ = c; }, bech_result.data.begin() + 1, bech_result.data.end()))
        {
            throw std::runtime_error(std::string("Wrong bech32 data: ") + address);
        }

        return data;

    }
};

}
