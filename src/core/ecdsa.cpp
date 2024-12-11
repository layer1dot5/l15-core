#include "ecdsa.hpp"

#include "key.h"
#include "interpreter.h"

#include "utils.hpp"

namespace l15::core {

bytevector EcdsaKeyPair::SignTxHash(const uint256 &sighash, unsigned char sighashtype) const
{
    signature sig_compact;

    unsigned char extra_entropy[32] = {0};

    secp256k1_ecdsa_signature sig;
    uint32_t counter = 0;
    if(!secp256k1_ecdsa_sign(m_ctx, &sig, sighash.begin(), m_sk.data(), secp256k1_nonce_function_rfc6979, extra_entropy))
        throw SignatureError("Signing error");

    secp256k1_ecdsa_signature_serialize_compact(m_ctx, sig_compact.data(), &sig);

    // Grind for low R
    while (sig_compact[0] & (uint8_t)0x80) {
        WriteLE32(extra_entropy, ++counter);
        if(!secp256k1_ecdsa_sign(m_ctx, &sig, sighash.begin(), m_sk.data(), secp256k1_nonce_function_rfc6979, extra_entropy))
            throw SignatureError("Signing error");

        secp256k1_ecdsa_signature_serialize_compact(m_ctx, sig_compact.data(), &sig);
    }

    // Additional verification step to prevent using a potentially corrupted signature
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(m_ctx, &pk, m_sk.data()))
        throw KeyError();

    if (!secp256k1_ecdsa_verify(secp256k1_context_static, &sig, sighash.begin(), &pk))
        throw SignatureError("Signature error");

    size_t sig_len = 72;
    bytevector sig_der;
    sig_der.resize(sig_len);

    secp256k1_ecdsa_signature_serialize_der(m_ctx, sig_der.data(), &sig_len, &sig);
    sig_der.resize(sig_len);

    sig_der.push_back(sighashtype);

    return sig_der;
}

bytevector EcdsaKeyPair::SignNonSegwitTx(const CMutableTransaction &tx, uint32_t nin, std::vector<CTxOut> spent_outputs, const CScript& pubkeyscript, const int hashtype) const
{
    uint256 sighash = SignatureHash(pubkeyscript, tx, nin, hashtype, spent_outputs[nin].nValue, SigVersion::BASE, nullptr);
    return SignTxHash(sighash, hashtype);
}

bytevector EcdsaKeyPair::SignSegwitV0Tx(const CMutableTransaction &tx, uint32_t nin, std::vector<CTxOut> spent_outputs, const CScript& pubkeyscript, const int hashtype) const
{
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::move(spent_outputs), true);

    uint256 sighash = SignatureHash(pubkeyscript, tx, nin, hashtype, txdata.m_spent_outputs[nin].nValue, SigVersion::WITNESS_V0, &txdata);

    return SignTxHash(sighash, hashtype);
}

compressed_pubkey EcdsaKeyPair::GetPubKey() const
{
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(m_ctx, &pk, m_sk.data()))
        throw WrongKey();

    compressed_pubkey res;
    size_t len = 33;

    if (!secp256k1_ec_pubkey_serialize(m_ctx, res.data(), &len, &pk, SECP256K1_EC_COMPRESSED))
        throw WrongKey();

    return res;
}

}
