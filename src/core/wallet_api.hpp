#pragma once

#include <string>
#include <vector>

#include "script/interpreter.h"

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

#include "common.hpp"

class CScript;

namespace l15::core {

class ChannelKeys;
class SignerApi;


//struct TxInputContainer
//{
//    CScript fundingscript;
//
//    uint256 txid;
//    uint32_t nout;
//    uint32_t sequence;
//};


class WalletApi
{
    friend class ChannelKeys;
    friend class SignerApi;

    secp256k1_context* m_ctx;

//    bytevector SignTxHash(const uint256 &sighash, unsigned char sighashtype, const bytevector &keystr) const;

public:
    WalletApi();
    ~WalletApi();

    const secp256k1_context* Secp256k1Context() const { return m_ctx; }

//    CScript ExtractScriptPubKey(const std::string& address) const;


//    std::string CreateKeyPair() const;
//    std::string CreateP2WPKHAddress(const bytevector &pubkey, const bytevector &privkey = bytevector()) const;
//    std::string CreateP2WSHAddress(const CScript& script) const;
//    bytevector SignSegwitTx(const bytevector &privkey, const CMutableTransaction &tx, const CAmount amount, int hashtype = SIGHASH_ALL) const;
    bytevector SignTaprootTx(const seckey &sk, const CMutableTransaction &tx, uint32_t nin, std::vector<CTxOut>&& spent_outputs, const CScript& spend_script, int hashtype = SIGHASH_DEFAULT) const;

//    void AddTxIn(CMutableTransaction& tx, const TxInputContainer txin) const;
//    void AddTxOut(CMutableTransaction& tx, const std::string &address, CAmount amount) const;

};

}
