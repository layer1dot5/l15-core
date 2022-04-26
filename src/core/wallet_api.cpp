#include <sstream>
#include <string>
#include <iostream>

#include "utils.hpp"
#include "wallet_api.hpp"

#include "util/strencodings.h"
#include "core_io.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "uint256.h"
#include "hash.h"


namespace l15::api {


const char* const WalletApi::HRP_MAINNET = "bc";
const char* const WalletApi::HRP_TESTNET = "tb";
const char* const WalletApi::HRP_REGTEST = "bcrt";


WalletApi::WalletApi(ChainMode mode): m_mode(mode)
{
    ECC_Start();
}


WalletApi::~WalletApi()
{
    ECC_Stop();
}


bytevector WalletApi::SignTxHash(const uint256 &sighash, unsigned char sighashtype, const bytevector &keydata) const
{
    CKey key;
    bytevector vchSig;

    key.Set(keydata.cbegin(), keydata.cend(), true);
    if (!key.IsValid()) {
        throw std::runtime_error("Error: Key not valid: " + HexStr(keydata));
    }

    if (!key.Sign(sighash, vchSig))
    {
        std::ostringstream buf;
        buf << "Error while sig hash is processed";
        throw std::runtime_error(buf.str());
    }
    else
    {
        vchSig.push_back(sighashtype);
    }

    return vchSig;
}

std::string WalletApi::CreateKeyPair() const
{
    CKey key;
    key.MakeNewKey(true);
    std::ostringstream out;

    CPubKey pub = key.GetPubKey();
    out << "pubkey=" << HexStr(Span<const unsigned char>(pub.data(), pub.size())) << std::endl;

    CPrivKey priv = key.GetPrivKey();
    out << "privkey=" << HexStr(Span<const unsigned char>(key.begin(), key.size())) << std::endl;
    return std::move(out.str());
}



bytevector WalletApi::SignSegwitTx(const bytevector &privkey, const CMutableTransaction &tx, const CAmount amount, const int hashtype) const
{

    CScript script(tx.vin[0].scriptWitness.stack.front().cbegin(), tx.vin[0].scriptWitness.stack.front().cend());

    uint256 sighash = SignatureHash(script, tx, 0, hashtype, amount, SigVersion::WITNESS_V0);

    std::ostringstream out;

    return SignTxHash(sighash, hashtype, privkey);
}

bytevector WalletApi::SignTaprootTx(const CKey &sk, const CMutableTransaction &tx, uint32_t nin, std::vector<CTxOut>&& spent_outputs, int hashtype) const
{
    uint256 sighash;
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::move(spent_outputs), true);

    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false; // Only support annex-less signing for now.

    //    if (sigversion == SigVersion::TAPSCRIPT) {
//        execdata.m_codeseparator_pos_init = true;
//        execdata.m_codeseparator_pos = 0xFFFFFFFF; // Only support non-OP_CODESEPARATOR BIP342 signing for now.
//        if (!leaf_hash) return false; // BIP342 signing needs leaf hash.
//        execdata.m_tapleaf_hash_init = true;
//        execdata.m_tapleaf_hash = *leaf_hash;
//    }

    if(!SignatureHashSchnorr(sighash, execdata, tx, nin, hashtype, SigVersion::TAPROOT, txdata, MissingDataBehavior::FAIL))
    {
        throw SignatureError();
    }

    bytevector sig;
    sig.resize(64);

    if(!sk.SignSchnorr(sighash, sig))
    {
        throw SignatureError();
    }

    if(hashtype)
    {
        sig.push_back(hashtype);
    }

    return sig;
}


std::string WalletApi::CreateP2WPKHAddress(const bytevector &pubkeydata, const bytevector &privkeydata) const
{
    auto pubkey = CPubKey(pubkeydata);
    if(!pubkey.IsFullyValid())
    {
        throw std::runtime_error(std::string("pubkey is invalid: ") + HexStr(pubkeydata));
    }
    if(!privkeydata.empty())
    {
        CKey key;
        key.Set(privkeydata.cbegin(), privkeydata.cend(), true);

        if(!key.VerifyPubKey(pubkey))
        {
            throw std::runtime_error("The Pubkey does not match the private key");
        }
    }

    uint160 pubkeyhash = Hash160(pubkey);
    return Bech32Encode(pubkeyhash.begin(), pubkeyhash.end());
}

std::string WalletApi::CreateP2WSHAddress(const CScript &script) const
{
    auto scripthash = ScriptHash(script);
    return Bech32Encode(scripthash.cbegin(), scripthash.cend());
}

bytevector WalletApi::Bech32Decode(const std::string& addrstr) const
{
    bech32::DecodeResult bech_result = bech32::Decode(addrstr);
    if(bech_result.hrp != GetHRP())
    {
        throw std::runtime_error(std::string("Bech32 prefix should be ") + GetHRP() + ". Address: " + addrstr);
    }
    if(bech_result.data.size() < 1)
    {
        throw std::runtime_error(std::string("Wrong bech32 data (no data decoded): ") + addrstr);
    }
    if(bech_result.data[0] == 0 && bech_result.encoding != bech32::Encoding::BECH32)
    {
        throw std::runtime_error("Version 0 witness address must use Bech32 checksum");
    }
    if(bech_result.data[0] != 0 && bech_result.encoding != bech32::Encoding::BECH32M)
    {
        throw std::runtime_error("Version 1+ witness address must use Bech32m checksum");
    }

    bytevector data;
    data.reserve(((bech_result.data.size() - 1) * 5) / 8);
    if(!ConvertBits<5, 8, false>([&](unsigned char c) { data.push_back(c); }, bech_result.data.begin() + 1, bech_result.data.end()))
    {
        throw std::runtime_error(std::string("Wrong bech32 data: ") + addrstr);
    }

    return data;
}

CScript WalletApi::ExtractScriptPubKey(const std::string &address) const
{
    auto addrdata = Bech32Decode(address);

    if(addrdata.size() == 20)
    {
        std::clog << "Spend to P2WPKH address: " << address << std::endl;
    }
    else if(addrdata.size() == 32)
    {
        std::clog << "Spend to P2WSH address: " << address << std::endl;
    }
    else
    {
        throw std::runtime_error(std::string("Wrong Bech32 address: ") + address);
    }

    CScript outpubkeyscript;
    outpubkeyscript << 0;
    outpubkeyscript << addrdata;

    return outpubkeyscript;
}

void WalletApi::AddTxIn(CMutableTransaction &tx, const TxInputContainer txin) const
{
    bytevector scripthash = ScriptHash(txin.fundingscript);
    std::clog << "Script hash:\t" << HexStr(scripthash) << std::endl;
    std::clog << "Spend from P2WSH address:\t" << Bech32Encode(scripthash.begin(), scripthash.end()) << std::endl;

    CTxIn input(txin.txid, txin.nout, CScript(), txin.sequence);
    tx.vin.emplace_back(input);
    tx.vin.front().scriptWitness.stack.emplace_back(bytevector(txin.fundingscript.begin(), txin.fundingscript.end()));
}

void WalletApi::AddTxOut(CMutableTransaction &tx, const std::string &address, CAmount amount) const
{
    tx.vout.emplace_back(CTxOut(amount, ExtractScriptPubKey(address)));
}

CKey WalletApi::CreateNewKey() const
{
    CKey key;
    key.MakeNewKey(true);
    return key;
}


}
