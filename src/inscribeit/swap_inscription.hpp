#pragma once

#include <string>

#include "script_merkle_tree.hpp"

#include "contract_builder.hpp"

#include "fee_calculator.hpp"

namespace l15::inscribeit {

class SwapInscriptionBuilder;
/*
template<>
class FeeCalculator<SwapInscriptionBuilder> {
public:
    FeeCalculator<SwapInscriptionBuilder>(std::string, std::string, std::string) {
        this->init();
    }

    void init();

    CAmount getFundsCommit() const { return m_fundsCommit; }
    CAmount getOrdinalCommit() const { return m_ordinalCommit; }
    CAmount getOrdinalSwap() const { return m_ordinalSwap; }
    CAmount getOrdinalTransfer() const { return m_ordinalTransfer; }

private:
    CAmount m_fundsCommit;
    CAmount m_ordinalCommit;
    CAmount m_ordinalSwap;
    CAmount m_ordinalTransfer;
};
*/
template<> class FeeCalculator<SwapInscriptionBuilder>;

class SwapInscriptionBuilder : public ContractBuilder
{
public:
    enum SwapPhase {
        OrdTerms,
        OrdCommitSig,
        FundsTerms,
        FundsCommitSig,
        MarketPayoffTerms,
        MarketPayoffSig,
        OrdSwapSig,
        FundsSwapSig,
        MarketSwapSig,
    };
private:
    static const uint32_t m_protocol_version;

    CAmount m_ord_price;
    std::optional<CAmount> m_market_fee;

    std::optional<xonly_pubkey> m_swap_script_pk_A;
    std::optional<xonly_pubkey> m_swap_script_pk_B;
    std::optional<xonly_pubkey> m_swap_script_pk_M;
    std::optional<bytevector> m_swap_hash;

    std::optional<seckey> m_ord_unspendable_key_factor;
    std::optional<std::string> m_ord_txid;
    std::optional<uint32_t> m_ord_nout;
    std::optional<CAmount> m_ord_amount;

    std::optional<CAmount> m_ord_commit_mining_fee_rate;
    std::optional<signature> m_ord_commit_sig;

    std::optional<seckey> m_funds_unspendable_key_factor;
    std::optional<std::string> m_funds_txid;
    std::optional<uint32_t> m_funds_nout;
    std::optional<CAmount> m_funds_amount;

    std::optional<signature> m_funds_commit_sig;

    std::optional<signature> m_ord_swap_sig_A;
    std::optional<signature> m_ord_swap_sig_M;

    std::optional<signature> m_funds_swap_sig_B;
    std::optional<signature> m_funds_swap_sig_M;
    std::optional<seckey> m_swap_preimage;

    std::optional<seckey> m_ordpayoff_unspendable_key_factor;
    std::optional<signature> m_ordpayoff_sig;


    std::optional<CMutableTransaction> mOrdCommitTx;
    std::optional<CMutableTransaction> mOrdPaybackTx;
    std::optional<CMutableTransaction> mFundsCommitTx;
    std::optional<CMutableTransaction> mFundsPaybackTx;

    std::optional<CMutableTransaction> mSwapTx;
    std::optional<CMutableTransaction> mOrdPayoffTx;

    std::tuple<xonly_pubkey, uint8_t, ScriptMerkleTree> OrdCommitTapRoot() const;
    std::tuple<xonly_pubkey, uint8_t, ScriptMerkleTree> FundsCommitTapRoot() const;
    std::tuple<xonly_pubkey, uint8_t, ScriptMerkleTree> OrdTransferTapRoot() const;

    CMutableTransaction MakeSwapTx(bool with_funds_in);

    std::shared_ptr<FeeCalculator<SwapInscriptionBuilder>> m_calculator;
public:
    const CMutableTransaction& GetOrdCommitTx();
    const CMutableTransaction& GetFundsCommitTx();
    const CMutableTransaction& GetSwapTx();
    const CMutableTransaction& GetPayoffTx();

    static const std::string name_ord_price;
    static const std::string name_market_fee;

    static const std::string name_swap_script_pk_A;
    static const std::string name_swap_script_pk_B;
    static const std::string name_swap_script_pk_M;
    static const std::string name_swap_hash;

    static const std::string name_ord_unspendable_key_factor;
    static const std::string name_ord_txid;
    static const std::string name_ord_nout;
    static const std::string name_ord_amount;

    static const std::string name_ord_commit_mining_fee_rate;
    static const std::string name_ord_commit_sig;

    static const std::string name_funds_unspendable_key_factor;
    static const std::string name_funds_txid;
    static const std::string name_funds_nout;
    static const std::string name_funds_amount;

    static const std::string name_funds_commit_sig;

    static const std::string name_ord_swap_sig_A;
    static const std::string name_ord_swap_sig_M;

    static const std::string name_swap_preimage;
    static const std::string name_funds_swap_sig_B;
    static const std::string name_funds_swap_sig_M;

    static const std::string name_ordpayoff_unspendable_key_factor;
    static const std::string name_ordpayoff_sig;

    explicit SwapInscriptionBuilder(): m_ord_price(0), m_market_fee(0),
    m_calculator(std::make_shared<FeeCalculator<SwapInscriptionBuilder>>("regtest", "0.000015", "0.0000015")) { }

    SwapInscriptionBuilder(const SwapInscriptionBuilder&) = default;
    SwapInscriptionBuilder(SwapInscriptionBuilder&&) noexcept = default;

    explicit SwapInscriptionBuilder(const std::string& chain_mode, const std::string& ord_price, const std::string& market_fee);

    SwapInscriptionBuilder& operator=(const SwapInscriptionBuilder& ) = default;
    SwapInscriptionBuilder& operator=(SwapInscriptionBuilder&& ) noexcept = default;

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

    std::string GetOrdCommitMiningFeeRate() const { return FormatAmount(m_ord_commit_mining_fee_rate.value()); }
    void SetOrdCommitMiningFeeRate(std::string v) { m_ord_commit_mining_fee_rate = ParseAmount(v); }
    void SetOrdCommitMiningFeeRate(CAmount v) { m_ord_commit_mining_fee_rate = v; }

    std::string GetOrdCommitSig() const { return hex(m_ord_commit_sig.value()); }
    void SetOrdCommitSig(std::string v) { m_ord_commit_sig = unhex<signature>(v); }

    void SignOrdCommitment(std::string sk);
    void SignOrdSwap(std::string sk);
    void SignOrdPayBack(std::string sk);


    std::string GetFundsUtxoTxId() const { return m_funds_txid.value(); }
    void SetFundsUtxoTxId(std::string v) { m_funds_txid = v; }

    uint32_t GetFundsUtxoNOut() const { return m_funds_nout.value(); }
    void SetFundsUtxoNOut(uint32_t v) { m_funds_nout = v; }

    std::string GetFundsUtxoAmount() const { return FormatAmount( m_funds_amount.value()); }
    void SetFundsUtxoAmount(std::string v) { m_funds_amount = ParseAmount(v); }

    std::string GetFundsUnspendableKeyFactor() const { return hex(m_funds_unspendable_key_factor.value()); }
    void SetFundsUnspendableKeyFactor(std::string v) { m_funds_unspendable_key_factor = unhex<seckey>(v); }

    std::string GetOrdPayoffUnspendableKeyFactor() const { return hex(m_ordpayoff_unspendable_key_factor.value()); }
    void SetOrdPayoffUnspendableKeyFactor(std::string v) { m_ordpayoff_unspendable_key_factor = unhex<seckey>(v); }


    std::string GetFundsCommitSig() const { return hex(m_funds_commit_sig.value()); }
    void SetFundsCommitSig(std::string v) { m_funds_commit_sig = unhex<signature>(v); }

    void SignFundsCommitment(std::string sk);
    void SignFundsSwap(std::string sk);
    void SignFundsPayBack(std::string sk);

    void MarketSignOrdPayoffTx(std::string sk);
    void MarketSignSwap(std::string preimage, std::string sk);

    void CheckContractTerms(SwapPhase phase);
    string Serialize(SwapPhase phase);
    void Deserialize(const string& data);

    string OrdCommitRawTransaction();
    string OrdPayBackRawTransaction();

    string FundsCommitRawTransaction();
    string FundsPayBackRawTransaction();

    string OrdSwapRawTransaction();
    string OrdPayoffRawTransaction();
};

    template<>
    class FeeCalculator<SwapInscriptionBuilder>: public Dummy<SwapInscriptionBuilder> {
    public:
        template<typename... _Args>
        FeeCalculator(_Args&&... args): Dummy<SwapInscriptionBuilder>(args...) {
            init();
        };

        void init() {
            uint32_t sampleNOutput = 0;
            std::string sampleOutput = "0000000000000000000000000000000000000000000000000000000000000000";

            l15::core::ChannelKeys m_swapScriptKeyA;
            l15::core::ChannelKeys m_swapScriptKeyB;
            l15::core::ChannelKeys m_swapScriptKeyM;
            l15::core::ChannelKeys m_ordUtxoKey;
            l15::core::ChannelKeys m_fundsUtxoKey;

            CMutableTransaction m_fundsCommit;
            CMutableTransaction m_ordCommit;
            CMutableTransaction m_ordSwap;
            CMutableTransaction m_ordTransfer;

            auto builder = getDummy();

            seckey preimage = l15::core::ChannelKeys::GetStrongRandomKey();
            bytevector swap_hash(32);
            CHash256().Write(preimage).Finalize(swap_hash);

            builder->SetOrdCommitMiningFeeRate("0.00001");
            builder->SetMiningFeeRate("0.00001");

            builder->SetSwapHash(hex(swap_hash));
            builder->SetSwapScriptPubKeyB(hex(m_swapScriptKeyB.GetLocalPubKey()));
            builder->SetSwapScriptPubKeyM(hex(m_swapScriptKeyM.GetLocalPubKey()));
            builder->SetSwapScriptPubKeyA(hex(m_swapScriptKeyA.GetLocalPubKey()));

            builder->SetOrdUtxoTxId(sampleOutput);
            builder->SetOrdUtxoNOut(sampleNOutput);
            builder->SetOrdUtxoAmount("1");

            builder->SignOrdCommitment(hex(m_ordUtxoKey.GetLocalPrivKey()));
            builder->SignOrdSwap(hex(m_swapScriptKeyA.GetLocalPrivKey()));

            builder->SetFundsUtxoTxId(sampleOutput);
            builder->SetFundsUtxoNOut(sampleNOutput);
            builder->SetFundsUtxoAmount("1");

            builder->SignFundsCommitment(hex(m_fundsUtxoKey.GetLocalPrivKey()));

            m_fundsCommit = builder->GetFundsCommitTx();
            m_ordCommit = builder->GetOrdCommitTx();

            builder->MarketSignOrdPayoffTx(hex(m_swapScriptKeyM.GetLocalPrivKey()));
            builder->SignFundsSwap(hex(m_swapScriptKeyB.GetLocalPrivKey()));
            builder->MarketSignSwap(hex(preimage), hex(m_swapScriptKeyM.GetLocalPrivKey()));

            m_ordSwap = builder->GetSwapTx();
            m_ordTransfer = builder->GetPayoffTx();
        }

        CAmount getFundsCommit() const { return m_fundsCommit; }
        CAmount getOrdinalCommit() const { return m_ordinalCommit; }
        CAmount getOrdinalSwap() const { return m_ordinalSwap; }
        CAmount getOrdinalTransfer() const { return m_ordinalTransfer; }

    private:
        CAmount m_fundsCommit;
        CAmount m_ordinalCommit;
        CAmount m_ordinalSwap;
        CAmount m_ordinalTransfer;
    };

}
