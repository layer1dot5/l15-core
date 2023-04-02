#pragma once

#include <string>

#include "contract_builder.hpp"

namespace l15::inscribeit {


class SwapInscriptionBuilder : public ContractBuilder
{
    static const uint32_t m_protocol_version = 1;

    std::optional<xonly_pubkey> m_swap_script_pk_A;
    std::optional<xonly_pubkey> m_swap_script_pk_B;
    std::optional<xonly_pubkey> m_swap_script_pk_M;
    std::optional<bytevector> m_swap_hash;

    std::optional<seckey> m_ord_unspendable_key_factor;
    std::optional<std::string> m_ord_txid;
    std::optional<uint32_t> m_ord_nout;
    std::optional<CAmount> m_ord_amount;

    std::optional<xonly_pubkey> m_ord_utxo_pk;
    std::optional<signature> m_ord_utxo_sig;

    std::optional<seckey> m_funds_unspendable_key_factor;
    std::optional<std::string> m_funds_txid;
    std::optional<uint32_t> m_funds_nout;
    std::optional<CAmount> m_funds_amount;

    std::optional<xonly_pubkey> m_funds_utxo_pk;
    std::optional<signature> m_funds_utxo_sig;

    std::optional<CMutableTransaction> mOrdCommitTx;
    std::optional<CMutableTransaction> mFundsCommitTx;

    xonly_pubkey OrdCommitTapRoot() const;
    xonly_pubkey FundsCommitTapRoot() const;

public:
    static const std::string name_ord_utxo_txid;
    static const std::string name_ord_utxo_nout;
    static const std::string name_ord_utxo_amount;
    static const std::string name_ord_unspendable_key_factor;
    static const std::string name_ord_utxo_pk_A;
    static const std::string name_ord_utxo_sig_A;

    static const std::string name_funds_utxo_txid;
    static const std::string name_funds_utxo_nout;
    static const std::string name_funds_utxo_amount;
    static const std::string name_funds_unspendable_key_factor;
    static const std::string name_funds_utxo_pk_B;
    static const std::string name_funds_utxo_sig_B;

    static const std::string name_swap_script_pk_M;
    static const std::string name_swap_hold_pk_M;
    static const std::string name_swap_fee_pk_M;

    SwapInscriptionBuilder() = default;
    SwapInscriptionBuilder(const SwapInscriptionBuilder&) = default;
    SwapInscriptionBuilder(SwapInscriptionBuilder&&) noexcept = default;

    SwapInscriptionBuilder& operator=(const SwapInscriptionBuilder& ) = default;
    SwapInscriptionBuilder& operator=(SwapInscriptionBuilder&& ) noexcept = default;

    explicit SwapInscriptionBuilder(const std::string& chain_mode) : ContractBuilder(chain_mode) {};

    uint32_t GetProtocolVersion() const override { return m_protocol_version; }

    std::string GetSwapScriptPubKeyA() const { return hex(m_swap_script_pk_A.value()); }
    void SetSwapScriptPubKeyA(std::string v) { m_swap_script_pk_A = unhex<xonly_pubkey>(v); }

    std::string GetSwapScriptPubKeyB() const { return hex(m_swap_script_pk_B.value()); }
    void SetSwapScriptPubKeyB(std::string v) { m_swap_script_pk_B = unhex<xonly_pubkey>(v); }

    std::string GetSwapScriptPubKeyM() const { return hex(m_swap_script_pk_M.value()); }
    void SetSwapScriptPubKeyM(std::string v) { m_swap_script_pk_M = unhex<xonly_pubkey>(v); }

    std::string GetSwapHash() const { return hex(m_swap_hash.value()); }
    void SetSwapHash(std::string v) { m_swap_hash = unhex<bytevector>(v); }

    std::string GetOrdUtxoTxId() const { return m_ord_txid.value(); }
    void SetOrdUtxoTxId(std::string v) { m_ord_txid = v; }

    uint32_t GetOrdUtxoNOut() const { return m_ord_nout.value(); }
    void SetOrdUtxoNOut(uint32_t v) { m_ord_nout = v; }

    std::string GetOrdUtxoAmount() const { return FormatAmount( m_ord_amount.value()); }
    void SetOrdUtxoAmount(std::string v) { m_ord_amount = ParseAmount(v); }

    std::string GetOrdUnspendableKeyFactor() const { return hex(m_ord_unspendable_key_factor.value()); }
    void SetOrdUnspendableKeyFactor(std::string v) { m_ord_unspendable_key_factor = unhex<seckey>(v); }

    std::string GetOrdUtxoPubKey() const { return hex(m_ord_utxo_pk.value()); }
    void SetOrdUtxoPubKey(std::string v) { m_ord_utxo_pk = unhex<xonly_pubkey>(v); }

    std::string GetOrdUtxoSig() const { return hex(m_ord_utxo_sig.value()); }
    void SetOrdUtxoSig(std::string v) { m_ord_utxo_sig = unhex<signature>(v); }

    void SignOrdUtxo(std::string ord_sk);


    std::string GetFundsUtxoTxId() const { return m_funds_txid.value(); }
    void SetFundsUtxoTxId(std::string v) { m_funds_txid = v; }

    uint32_t GetFundsUtxoNOut() const { return m_funds_nout.value(); }
    void SetFundsUtxoNOut(uint32_t v) { m_funds_nout = v; }

    std::string GetFundsUtxoAmount() const { return FormatAmount( m_funds_amount.value()); }
    void SetFundsUtxoAmount(std::string v) { m_funds_amount = ParseAmount(v); }

    std::string GetFundsUnspendableKeyFactor() const { return hex(m_funds_unspendable_key_factor.value()); }
    void SetFundsUnspendableKeyFactor(std::string v) { m_funds_unspendable_key_factor = unhex<seckey>(v); }

    std::string GetFundsFundsUtxoPubKey() const { return hex(m_funds_utxo_pk.value()); }
    void SetFundsUtxoPubKey(std::string v) { m_funds_utxo_pk = unhex<xonly_pubkey>(v); }

    std::string GetFundsUtxoSig() const { return hex(m_funds_utxo_sig.value()); }
    void SetFundsUtxoSig(std::string v) { m_funds_utxo_sig = unhex<signature>(v); }

    void SignFundsUtxo(std::string sk);


    string Serialize();

    void Deserialize(string hex_data);

    string OrdCommitRawTransaction();

    string FundsCommitRawTransaction();
};

}
