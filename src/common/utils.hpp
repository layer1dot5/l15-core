#pragma once

#include <string>
#include <vector>

#include "smartinserter.hpp"

#include "bech32.h"
#include "util/strencodings.h"
#include "crypto/sha256.h"
#include "script/script.h"
#include "uint256.h"
#include "amount.h"

#include "common.hpp"
#include "feerate.h"
#include "consensus.h"
#include "policy.h"

namespace l15 {

CAmount ParseAmount(const std::string& amountstr);
std::string FormatAmount(CAmount amount);
CAmount CalculateOutputAmount(CAmount input_amount, CAmount fee_rate, const CMutableTransaction&);
template<typename T> CAmount CalculateTxFee(CAmount fee_rate, const T& tx);
constexpr CAmount Dust(const CAmount fee_rate = DUST_RELAY_TX_FEE) {return CFeeRate(fee_rate).GetFee(43 + 32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4);}

bytevector ScriptHash(const CScript &script);
bytevector CreatePreimage();

template <typename DATA>
bytevector Hash160(const DATA& preimage)
{
    bytevector hash160(CHash160::OUTPUT_SIZE);
    CHash160().Write(preimage).Finalize(hash160);
    return hash160;
}

CAmount GetOutputAmount(const std::string& txoutstr);
uint32_t GetCsvInBlocks(uint32_t blocks);

template <typename T> void LogTx(const T& tx);

enum ChainType {BTC, L15};
enum ChainMode {MAINNET, TESTNET, REGTEST};

template <ChainType C, ChainMode M> struct Hrp;
template <> struct Hrp<BTC, MAINNET> { const static char* const value; };
template <> struct Hrp<BTC, TESTNET> { const static char* const value; };
template <> struct Hrp<BTC, REGTEST> { const static char* const value; };
template <> struct Hrp<L15, MAINNET> { const static char* const value; };
template <> struct Hrp<L15, TESTNET> { const static char* const value; };
template <> struct Hrp<L15, REGTEST> { const static char* const value; };


class Bech32
{
    ChainType chaintype;
    ChainMode chainmode;
    const char* hrptag;
public:
    Bech32() : Bech32(BTC, MAINNET) {}
    Bech32(ChainType c, ChainMode m) : chaintype(c), chainmode(m),
        hrptag(chaintype == L15
            ? (m == MAINNET ? Hrp<L15, MAINNET>::value : (m == TESTNET ? Hrp<L15, TESTNET>::value : Hrp<L15, REGTEST>::value))
            : (m == MAINNET ? Hrp<BTC, MAINNET>::value : (m == TESTNET ? Hrp<BTC, TESTNET>::value : Hrp<BTC, REGTEST>::value)))
    {}

    Bech32(const Bech32& ) = default;
    Bech32& operator=(const Bech32& o) = default;

    ChainType GetChaintype() const
    { return chaintype; }

    ChainMode GetChainMode() const
    { return chainmode; }

    template <typename KeyType>
    std::string Encode(const KeyType& pk, bech32::Encoding encoding = bech32::Encoding::BECH32M) const {
        std::vector<unsigned char> bech32buf = {(encoding == bech32::Encoding::BECH32) ? (uint8_t)0 : (uint8_t)1};
        bech32buf.reserve(1 + ((pk.end() - pk.begin()) * 8 + 4) / 5);
        ConvertBits<8, 5, true>([&](unsigned char c) { bech32buf.push_back(c); }, pk.begin(), pk.end());
        return bech32::Encode(encoding, hrptag, bech32buf);
    }

    std::tuple<unsigned, l15::bytevector> Decode(const std::string& address) const
    {
        bech32::DecodeResult bech_result = bech32::Decode(address);
        if(bech_result.hrp != hrptag)
        {
            throw std::invalid_argument(std::string("Allowed prefix: ") + hrptag + ". Address: " + address);
        }
        if(bech_result.data.empty())
        {
            throw std::invalid_argument(std::string("Wrong bech32 data (no data decoded): ") + address);
        }
        if(bech_result.data[0] == 0 && bech_result.encoding != bech32::Encoding::BECH32)
        {
            throw std::invalid_argument("Version 0 witness address must use Bech32 checksum");
        }
        if(bech_result.data[0] != 0 && bech_result.encoding != bech32::Encoding::BECH32M)
        {
            throw std::invalid_argument("Version 1+ witness address must use Bech32m checksum");
        }

        bytevector data;
        data.reserve(32);
        auto I = cex::smartinserter(data, data.end());
        if(!ConvertBits<5, 8, false>([&](unsigned char c) { *I = c; ++I; }, bech_result.data.begin() + 1, bech_result.data.end()))
        {
            throw std::invalid_argument(std::string("Wrong bech32 data: ") + address);
        }

        return std::tie(bech_result.data[0], data);
    }

    CScript PubKeyScript(const std::string& addr) const
    {
        auto res = Decode(addr);
        return CScript() << get<0>(res) << get<1>(res);
    }
};

}
