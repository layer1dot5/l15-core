#pragma once

#include "smartinserter.hpp"

#include "script/script.h"
#include "bech32.h"

#include "bech32_hrp.hpp"

namespace l15 {

class NotBech32Encoding : public IllegalArgument
{
public:
    explicit NotBech32Encoding(std::string&& details) noexcept : IllegalArgument(move(details)) {}
    ~NotBech32Encoding() override = default;

    const char* what() const noexcept override
    { return "NotBech32Encoding"; }

};

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

    const char* GetHrp() const
    { return hrptag; }

    template <typename KeyType>
    std::string Encode(const KeyType& pk, bech32::Encoding encoding = bech32::Encoding::BECH32M) const {
        std::vector<unsigned char> bech32buf = {(encoding == bech32::Encoding::BECH32) ? (uint8_t)0 : (uint8_t)1};
        bech32buf.reserve(1 + ((pk.end() - pk.begin()) * 8 + 4) / 5);
        ConvertBits<8, 5, true>([&](unsigned char c) { bech32buf.push_back(c); }, pk.begin(), pk.end());
        return bech32::Encode(encoding, hrptag, bech32buf);
    }

    std::tuple<unsigned, bytevector> Decode(const std::string& address) const
    {
        bech32::DecodeResult bech_result = bech32::Decode(address);
        if (bech_result.encoding == bech32::Encoding::INVALID)
            throw NotBech32Encoding(std::string(address));
        if (bech_result.hrp != hrptag)
            throw IllegalArgument(std::string("Allowed prefix: ") + hrptag + ". Address: " + address);
        if (bech_result.data.empty())
            throw IllegalArgument(std::string("Wrong bech32 data (no data decoded): ") + address);
        if (bech_result.data[0] == 0 && bech_result.encoding != bech32::Encoding::BECH32)
            throw IllegalArgument("Version 0 witness address must use Bech32 checksum");
        if (bech_result.data[0] != 0 && bech_result.encoding != bech32::Encoding::BECH32M)
            throw IllegalArgument("Version 1+ witness address must use Bech32m checksum");

        bytevector data;
        data.reserve(32);
        auto I = cex::smartinserter(data, data.end());
        if(!ConvertBits<5, 8, false>([&](unsigned char c) { *I = c; ++I; }, bech_result.data.begin() + 1, bech_result.data.end()))
        {
            throw IllegalArgument(std::string("Wrong bech32 data: ") + address);
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