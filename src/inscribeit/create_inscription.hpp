#pragma once

#include <string>
#include <sstream>
#include <vector>
#include <optional>
#include <memory>

#include "univalue.h"

#include "common.hpp"
#include "contract_builder.hpp"

namespace l15::inscribeit {

class CreateInscriptionBuilder;

class CreateInscriptionBuilder: public ContractBuilder
{
    static const uint32_t m_protocol_version;

    std::optional<std::string> m_txid;
    std::optional<uint32_t> m_nout;
    std::optional<CAmount> m_amount;

    std::optional<std::string> m_content_type;
    std::optional<bytevector> m_content;

    std::optional<xonly_pubkey> m_utxo_pk; //taproot
    std::optional<signature> m_utxo_sig;

    std::optional<xonly_pubkey> m_insribe_script_pk;
    std::optional<signature> m_inscribe_script_sig;

    std::optional<seckey> m_inscribe_taproot_sk; // needed in case of a fallback scenario to return funds
    std::optional<xonly_pubkey> m_inscribe_int_pk; //taproot

    std::optional<xonly_pubkey> m_destination_pk;

    std::optional<CMutableTransaction> mFundingTx;
    std::optional<CMutableTransaction> mGenesisTx;

private:
    void CheckBuildArgs() const;
    void CheckRestoreArgs(const UniValue& params) const;
    //void CheckTransactionsExistence() const;

    void RestoreTransactions();

public:

    static const std::string name_utxo_txid;
    static const std::string name_utxo_nout;
    static const std::string name_utxo_amount;
    static const std::string name_utxo_pk;
    static const std::string name_content_type;
    static const std::string name_content;
    static const std::string name_utxo_sig;
    static const std::string name_inscribe_script_pk;
    static const std::string name_inscribe_int_pk;
    static const std::string name_inscribe_sig;
    static const std::string name_destination_pk;

    CreateInscriptionBuilder() = default;
    CreateInscriptionBuilder(const CreateInscriptionBuilder&) = default;
    CreateInscriptionBuilder(CreateInscriptionBuilder&&) noexcept = default;

    CreateInscriptionBuilder& operator=(const CreateInscriptionBuilder&) = default;
    CreateInscriptionBuilder& operator=(CreateInscriptionBuilder&&) noexcept = default;

    explicit CreateInscriptionBuilder(const std::string& chain_mode) : ContractBuilder(chain_mode) { };

    uint32_t GetProtocolVersion() const override { return m_protocol_version; }

    //const CMutableTransaction GetFundingTx() const;
    //const CMutableTransaction GetGenesisTx() const;

    CMutableTransaction CreateFundingTxTemplate() const;
    CMutableTransaction CreateGenesisTxTemplate(const std::string &content_type, const l15::bytevector &content) const;

    CAmount GetFeeForContent(const std::string &content_type, const std::string &hex_content, CAmount fee_rate);

    std::string GetUtxoTxId() const { return m_txid.value(); }
    void SetUtxoTxId(std::string v) { m_txid = v; }

    uint32_t GetUtxoNOut() const { return m_nout.value(); }
    void SetUtxoNOut(uint32_t v) { m_nout = v; }

    std::string GetUtxoAmount() const { return FormatAmount( m_amount.value()); }
    void SetUtxoAmount(std::string v) { m_amount = ParseAmount(v); }

    std::string GetContentType() const { return m_content_type.value(); }
    void SetContentType(std::string v) { m_content_type = v; }

    std::string GetContent() const { return l15::hex(m_content.value()); }
    void SetContent(std::string v) { m_content = unhex<bytevector>(v); }

    std::string GetDestinationPubKey() const { return l15::hex(m_destination_pk.value()); }
    void SetDestinationPubKey(std::string v) { m_destination_pk = unhex<xonly_pubkey>(v); }

    std::string GetIntermediateSecKey() const { return l15::hex(m_inscribe_taproot_sk.value()); }

    CreateInscriptionBuilder& UTXO(const std::string& txid, uint32_t nout, const std::string& amount);
    CreateInscriptionBuilder& Data(const std::string& content_type, const std::string& hex_data);
    CreateInscriptionBuilder& FeeRate(const std::string& rate);
    CreateInscriptionBuilder& Destination(const std::string& pk);

    std::string IntermediateTaprootPrivKey() const
    { return hex(m_inscribe_taproot_sk.value()); }

    std::string GetUtxoPubKey() const
    { return hex(m_utxo_pk.value()); }

    std::string GetUtxoSig() const
    { return hex(m_utxo_sig.value()); }

    std::string GetInscribeScriptPubKey() const
    { return hex(m_insribe_script_pk.value()); }

    std::string GetInscribeScriptSig() const
    { return hex(m_inscribe_script_sig.value()); }

    std::string GetInscribeInternaltPubKey() const
    { return hex(m_inscribe_int_pk.value()); }

    void Sign(std::string utxo_sk);

    std::vector<CMutableTransaction> getTransactions() override;

    std::vector<std::string> RawTransactions() const;

    std::string Serialize() const;
    void Deserialize(const std::string& data);

};

} // inscribeit

