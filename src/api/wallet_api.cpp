#include <sstream>
#include <string>
#include <iostream>

#include "utils.hpp"
#include "wallet_api.hpp"
#include "channel_keys.hpp"
#include "script_merkle_tree.hpp"

#include "util/strencodings.h"
#include "core_io.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"

#include "secp256k1_schnorrsig.h"


namespace l15::core {


WalletApi::WalletApi()
{
    m_ctx = ChannelKeys::GetStaticSecp256k1Context();
}



//bytevector WalletApi::SignTxHash(const uint256 &sighash, unsigned char sighashtype, const bytevector &keydata) const
//{
//    CKey key;
//    bytevector vchSig;
//
//    key.Set(keydata.cbegin(), keydata.cend(), true);
//    if (!key.IsValid()) {
//        throw std::runtime_error("Error: Key not valid: " + HexStr(keydata));
//    }
//
//    if (!key.Sign(sighash, vchSig))
//    {
//        std::ostringstream buf;
//        buf << "Error while sig hash is processed";
//        throw std::runtime_error(buf.str());
//    }
//    else
//    {
//        vchSig.push_back(sighashtype);
//    }
//
//    return vchSig;
//}

//std::string WalletApi::CreateKeyPair() const
//{
//    CKey key;
//    key.MakeNewKey(true);
//    std::ostringstream out;
//
//    CPubKey pub = key.GetPubKey();
//    out << "pubkey=" << HexStr(Span<const unsigned char>(pub.data(), pub.size())) << std::endl;
//
//    CPrivKey priv = key.GetPrivKey();
//    out << "privkey=" << HexStr(Span<const unsigned char>(key.begin(), key.size())) << std::endl;
//    return std::move(out.str());
//}



//bytevector WalletApi::SignSegwitTx(const bytevector &privkey, const CMutableTransaction &tx, const CAmount amount, const int hashtype) const
//{
//
//    CScript script(tx.vin[0].scriptWitness.stack.front().cbegin(), tx.vin[0].scriptWitness.stack.front().cend());
//
//    uint256 sighash = SignatureHash(script, tx, 0, hashtype, amount, SigVersion::WITNESS_V0);
//
//    std::ostringstream out;
//
//    return SignTxHash(sighash, hashtype, privkey);
//}

bytevector WalletApi::SignTaprootTx(const seckey &sk, const CMutableTransaction &tx, uint32_t nin, std::vector<CTxOut>&& spent_outputs, const CScript& spend_script, int hashtype) const
{
    uint256 sighash;
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::move(spent_outputs), true);

    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false; // Only support annex-less signing for now.

    if(!spend_script.empty()) {
        execdata.m_codeseparator_pos_init = true;
        execdata.m_codeseparator_pos = 0xFFFFFFFF; // Only support non-OP_CODESEPARATOR BIP342 signing for now.
        execdata.m_tapleaf_hash_init = true;
        execdata.m_tapleaf_hash = TapLeafHash(spend_script);
    }

    if(!SignatureHashSchnorr(sighash, execdata, tx, nin, hashtype, execdata.m_tapleaf_hash_init ? SigVersion::TAPSCRIPT : SigVersion::TAPROOT, txdata, MissingDataBehavior::FAIL))
    {
        throw SignatureError("Sighash generation error");
    }

    bytevector sig;
    uint256 aux;
    sig.resize(64);

    {
        // TODO: this block is copy-pasted from CKey bitcoin class
        //       Should be replaced usin proper abstraction layer (ChannelKeys??)
        secp256k1_keypair keypair;
        if (!secp256k1_keypair_create(Secp256k1Context(), &keypair, sk.data())) throw SignatureError("Key error");
//        if (merkle_root) {
//            secp256k1_xonly_pubkey pubkey;
//            if (!secp256k1_keypair_xonly_pub(secp256k1_context_sign, &pubkey, nullptr, &keypair)) return false;
//            unsigned char pubkey_bytes[32];
//            if (!secp256k1_xonly_pubkey_serialize(secp256k1_context_sign, pubkey_bytes, &pubkey)) return false;
//            uint256 tweak = XOnlyPubKey(pubkey_bytes).ComputeTapTweakHash(merkle_root->IsNull() ? nullptr : merkle_root);
//            if (!secp256k1_keypair_xonly_tweak_add(GetVerifyContext(), &keypair, tweak.data())) return false;
//        }
        bool ret = secp256k1_schnorrsig_sign32(Secp256k1Context(), sig.data(), sighash.data(), &keypair, aux.data());
        if (ret) {
            // Additional verification step to prevent using a potentially corrupted signature
            secp256k1_xonly_pubkey pubkey_verify;
            ret = secp256k1_keypair_xonly_pub(Secp256k1Context(), &pubkey_verify, nullptr, &keypair);
            ret &= secp256k1_schnorrsig_verify(Secp256k1Context(), sig.data(), sighash.data(), 32, &pubkey_verify);
        }
        if (!ret) memory_cleanse(sig.data(), sig.size());
        memory_cleanse(&keypair, sizeof(keypair));

        if (!ret) throw SignatureError("Signing error");
    }





    if(hashtype)
    {
        sig.push_back(hashtype);
    }

    return sig;
}


//std::string WalletApi::CreateP2WPKHAddress(const bytevector &pubkeydata, const bytevector &privkeydata) const
//{
//    auto pubkey = CPubKey(pubkeydata);
//    if(!pubkey.IsFullyValid())
//    {
//        throw std::runtime_error(std::string("pubkey is invalid: ") + HexStr(pubkeydata));
//    }
//    if(!privkeydata.empty())
//    {
//        CKey key;
//        key.Set(privkeydata.cbegin(), privkeydata.cend(), true);
//
//        if(!key.VerifyPubKey(pubkey))
//        {
//            throw std::runtime_error("The Pubkey does not match the private key");
//        }
//    }
//
//    uint160 pubkeyhash = Hash160(pubkey);
//    return Bech32Encode(pubkeyhash.begin(), pubkeyhash.end());
//}
//
//std::string WalletApi::CreateP2WSHAddress(const CScript &script) const
//{
//    auto scripthash = ScriptHash(script);
//    return Bech32Encode(scripthash.cbegin(), scripthash.cend());
//}


//CScript WalletApi::ExtractScriptPubKey(const std::string &address) const
//{
//    auto addrdata = Bech32Decode(address);
//
//    if(addrdata.size() == 20)
//    {
//        std::clog << "Spend to P2WPKH address: " << address << std::endl;
//    }
//    else if(addrdata.size() == 32)
//    {
//        std::clog << "Spend to P2WSH address: " << address << std::endl;
//    }
//    else
//    {
//        throw std::runtime_error(std::string("Wrong Bech32 address: ") + address);
//    }
//
//    CScript outpubkeyscript;
//    outpubkeyscript << 0;
//    outpubkeyscript << addrdata;
//
//    return outpubkeyscript;
//}
//
//void WalletApi::AddTxIn(CMutableTransaction &tx, const TxInputContainer txin) const
//{
//    bytevector scripthash = ScriptHash(txin.fundingscript);
//    std::clog << "Script hash:\t" << HexStr(scripthash) << std::endl;
//    std::clog << "Spend from P2WSH address:\t" << Bech32Encode(scripthash.begin(), scripthash.end()) << std::endl;
//
//    CTxIn input(txin.txid, txin.nout, CScript(), txin.sequence);
//    tx.vin.emplace_back(input);
//    tx.vin.front().scriptWitness.stack.emplace_back(bytevector(txin.fundingscript.begin(), txin.fundingscript.end()));
//}
//
//void WalletApi::AddTxOut(CMutableTransaction &tx, const std::string &address, CAmount amount) const
//{
//    tx.vout.emplace_back(CTxOut(amount, ExtractScriptPubKey(address)));
//}

}
