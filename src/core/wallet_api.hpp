#pragma once

#include "pubkey.h"

#include <string>
#include <vector>

#include "script/interpreter.h"
#include "util/strencodings.h"
#include "bech32.h"

#include "common.hpp"
#include "common_api.hpp"

class CScript;

namespace l15::api {


struct TxInputContainer
{
    CScript fundingscript;

    uint256 txid;
    uint32_t nout;
    uint32_t sequence;
};

class WalletApi
{
    const ChainMode m_mode;
    ECCVerifyHandle eccVerifyHandle;

    static const char* const HRP_MAINNET;
    static const char* const HRP_TESTNET;
    static const char* const HRP_REGTEST;

    const char* const GetHRP() const
    {
        switch(m_mode)
        {
        case ChainMode::MODE_MAINNET:
            return HRP_MAINNET;
        case ChainMode::MODE_TESTNET:
            return HRP_TESTNET;
        case ChainMode::MODE_REGTEST:
            return HRP_REGTEST;
        default:
            throw std::runtime_error("Wrong chain mode: " + std::to_string(static_cast<int>(m_mode)));
        }
    }
    bytevector SignTxHash(const uint256 &sighash, unsigned char sighashtype, const bytevector &keystr) const;
public:
    explicit WalletApi(ChainMode mode);
    ~WalletApi();

    template <class I>
    std::string Bech32Encode(I begin, I end) const
    {
        std::vector<unsigned char> bech32buf = {'\0'};
        bech32buf.reserve(1 + ((end - begin) * 8 + 4) / 5);
        ConvertBits<8, 5, true>([&](unsigned char c) { bech32buf.push_back(c); }, begin, end);
        return bech32::Encode(bech32::Encoding::BECH32, GetHRP(), bech32buf);
    }
    bytevector Bech32Decode(const std::string& addrstr) const;

    CScript ExtractScriptPubKey(const std::string& address) const;


    std::string CreateKeyPair() const;
    std::string CreateP2WPKHAddress(const bytevector &pubkey, const bytevector &privkey = bytevector()) const;
    std::string CreateP2WSHAddress(const CScript& script) const;
    bytevector SignSegwitTx(const bytevector &privkey, const CMutableTransaction &tx, const CAmount amount, int hashtype = SIGHASH_ALL) const;

    void AddTxIn(CMutableTransaction& tx, const TxInputContainer txin) const;
    void AddTxOut(CMutableTransaction& tx, const std::string &address, CAmount amount) const;
};

}
