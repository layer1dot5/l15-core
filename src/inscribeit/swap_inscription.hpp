#pragma once

#include <string>

#include "script_merkle_tree.hpp"

#include "contract_builder.hpp"

namespace l15::inscribeit {

enum SwapPhase {
    ORD_TERMS,
    FUNDS_TERMS,
    FUNDS_COMMIT_SIG,
    MARKET_PAYOFF_TERMS,
    MARKET_PAYOFF_SIG,
    ORD_SWAP_SIG,
    FUNDS_SWAP_SIG,
    MARKET_SWAP_SIG,
};

class SwapInscriptionBuilder : public ContractBuilder
{
    CAmount m_whole_fee = 0;
    CAmount m_last_fee_rate = 0;

    static const uint32_t m_protocol_version;

    CAmount m_ord_price;
    std::optional<CAmount> m_market_fee;

    std::optional<xonly_pubkey> m_swap_script_pk_A;
    std::optional<xonly_pubkey> m_swap_script_pk_B;
    std::optional<xonly_pubkey> m_swap_script_pk_M;

    std::optional<std::string> m_ord_txid;
    std::optional<uint32_t> m_ord_nout;
    std::optional<CAmount> m_ord_amount;
    std::optional<xonly_pubkey> m_ord_pk;

    std::optional<seckey> m_funds_unspendable_key_factor;
    std::optional<std::string> m_funds_txid;
    std::optional<uint32_t> m_funds_nout;
    std::optional<CAmount> m_funds_amount;

    std::optional<signature> m_funds_commit_sig;

    std::optional<signature> m_ord_swap_sig_A;

    std::optional<signature> m_funds_swap_sig_B;
    std::optional<signature> m_funds_swap_sig_M;

    std::optional<signature> m_ordpayoff_sig;

    mutable std::optional<CMutableTransaction> mFundsCommitTx;
    mutable std::optional<CMutableTransaction> mFundsPaybackTx;

    mutable std::optional<CMutableTransaction> mSwapTx;
    mutable std::optional<CMutableTransaction> mOrdPayoffTx;

    std::tuple<xonly_pubkey, uint8_t, ScriptMerkleTree> FundsCommitTapRoot() const;

    CMutableTransaction MakeSwapTx(bool with_funds_in) const;

    void CheckOrdSwapSig() const;
    void CheckFundsSwapSig() const;

    void CheckOrdPayoffSig() const;

    std::tuple<xonly_pubkey, uint8_t, ScriptMerkleTree> TemplateTapRoot() const;

public:
    CMutableTransaction CreatePayoffTxTemplate() const;
    CMutableTransaction CreateSwapTxTemplate(bool with_funds_in) const;
    CMutableTransaction CreateFundsCommitTxTemplate() const;

    const CMutableTransaction& GetFundsCommitTx() const;
    const CMutableTransaction& GetSwapTx() const;
    const CMutableTransaction& GetPayoffTx() const;

    static const std::string name_ord_price;
    static const std::string name_market_fee;

    static const std::string name_swap_script_pk_A;
    static const std::string name_swap_script_pk_B;
    static const std::string name_swap_script_pk_M;

    static const std::string name_ord_txid;
    static const std::string name_ord_nout;
    static const std::string name_ord_amount;
    static const std::string name_ord_pk;

    static const std::string name_funds_unspendable_key_factor;
    static const std::string name_funds_txid;
    static const std::string name_funds_nout;
    static const std::string name_funds_amount;

    static const std::string name_funds_commit_sig;

    static const std::string name_ord_swap_sig_A;

    static const std::string name_funds_swap_sig_B;
    static const std::string name_funds_swap_sig_M;

    static const std::string name_ordpayoff_unspendable_key_factor;
    static const std::string name_ordpayoff_sig;

    explicit SwapInscriptionBuilder(): m_ord_price(0), m_market_fee(0) {}

    SwapInscriptionBuilder(const SwapInscriptionBuilder&) = default;
    SwapInscriptionBuilder(SwapInscriptionBuilder&&) noexcept = default;

    explicit SwapInscriptionBuilder(const std::string& ord_price, const std::string& market_fee);

    SwapInscriptionBuilder& operator=(const SwapInscriptionBuilder& ) = default;
    SwapInscriptionBuilder& operator=(SwapInscriptionBuilder&& ) noexcept = default;

    uint32_t GetProtocolVersion() const override { return m_protocol_version; }

    SwapInscriptionBuilder& MiningFeeRate(const std::string& fee_rate) { SetMiningFeeRate(fee_rate); return *this; }
    SwapInscriptionBuilder& OrdUTXO(const std::string& txid, uint32_t nout, const std::string& amount);
    SwapInscriptionBuilder& FundsUTXO(const std::string& txid, uint32_t nout, const std::string& amount);

    SwapInscriptionBuilder& SwapScriptPubKeyA(const std::string& v) { m_swap_script_pk_A = unhex<xonly_pubkey>(v); return *this; }
    SwapInscriptionBuilder& SwapScriptPubKeyB(const std::string& v) { m_swap_script_pk_B = unhex<xonly_pubkey>(v); return *this; }

    std::string GetSwapScriptPubKeyM() const { return hex(m_swap_script_pk_M.value()); }
    void SetSwapScriptPubKeyM(const std::string& v) { m_swap_script_pk_M = unhex<xonly_pubkey>(v); }

    void SignOrdSwap(const std::string& sk);

    std::string GetFundsCommitSig() const { return hex(m_funds_commit_sig.value()); }
    void SetFundsCommitSig(std::string v) { m_funds_commit_sig = unhex<signature>(v); }

    void SignFundsCommitment(const std::string& sk);
    void SignFundsSwap(const std::string& sk);
    void SignFundsPayBack(const std::string& sk);

    void MarketSignOrdPayoffTx(const std::string& sk);
    void MarketSignSwap(const std::string& sk);

    void CheckContractTerms(SwapPhase phase) const;
    std::string Serialize(SwapPhase phase);
    void Deserialize(const std::string& data);

    std::string FundsCommitRawTransaction();
    std::string FundsPayBackRawTransaction();

    string OrdSwapRawTransaction();
    string OrdPayoffRawTransaction();

    std::vector<std::pair<CAmount,CMutableTransaction>> GetTransactions() const override;
    std::string GetMinFundingAmount() const override;
};

} // namespace l15::inscribeit
