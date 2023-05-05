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
    CAmount m_ord_amount;

    std::list<Transfer> m_utxo;

    std::optional<std::string> m_collection_id;
    std::optional<Transfer> m_collection_utxo;

    std::optional<std::string> m_content_type;
    std::optional<bytevector> m_content;

    std::optional<xonly_pubkey> m_inscribe_script_pk;
    std::optional<signature> m_inscribe_script_sig;

    std::optional<seckey> m_inscribe_taproot_sk; // needed in case of a fallback scenario to return funds
    std::optional<seckey> m_inscribe_int_sk; //taproot
    std::optional<xonly_pubkey> m_inscribe_int_pk; //taproot

    std::optional<xonly_pubkey> m_destination_pk;

    mutable std::optional<CMutableTransaction> mCommitTx;
    mutable std::optional<CMutableTransaction> mGenesisTx;

private:
    void CheckBuildArgs() const;
    void CheckAmount() const;

    void RestoreTransactions();

protected:
    std::vector<std::pair<CAmount,CMutableTransaction>> GetTransactions() const override;

    CMutableTransaction CreateCommitTxTemplate() const;
    CMutableTransaction CreateGenesisTxTemplate() const;

    const CMutableTransaction& CommitTx() const;

public:

    static const std::string name_ord_amount;
    static const std::string name_utxo;
    static const std::string name_utxo_txid;
    static const std::string name_utxo_nout;
    static const std::string name_utxo_amount;
    static const std::string name_utxo_pk;
    static const std::string name_content_type;
    static const std::string name_content;
    static const std::string name_utxo_sig;
    static const std::string name_collection;
    static const std::string name_collection_id;
    static const std::string name_inscribe_script_pk;
    static const std::string name_inscribe_int_pk;
    static const std::string name_inscribe_sig;
    static const std::string name_destination_pk;

    CreateInscriptionBuilder() : m_ord_amount(0) {}
    CreateInscriptionBuilder(const CreateInscriptionBuilder&) = default;
    CreateInscriptionBuilder(CreateInscriptionBuilder&&) noexcept = default;

    explicit CreateInscriptionBuilder(const std::string& amount) : m_ord_amount(ParseAmount(amount)) {}

    CreateInscriptionBuilder& operator=(const CreateInscriptionBuilder&) = default;
    CreateInscriptionBuilder& operator=(CreateInscriptionBuilder&&) noexcept = default;

    uint32_t GetProtocolVersion() const override { return m_protocol_version; }

    std::string GetContentType() const { return m_content_type.value(); }
    void SetContentType(std::string v) { m_content_type = v; }

    std::string GetContent() const { return l15::hex(m_content.value()); }
    void SetContent(std::string v) { m_content = unhex<bytevector>(v); }

    std::string GetDestinationPubKey() const { return l15::hex(m_destination_pk.value()); }
    void SetDestinationPubKey(std::string v) { m_destination_pk = unhex<xonly_pubkey>(v); }

    std::string GetIntermediateSecKey() const { return l15::hex(m_inscribe_taproot_sk.value()); }

    CreateInscriptionBuilder& MiningFeeRate(const std::string& rate);
    CreateInscriptionBuilder& AddUTXO(const string &txid, uint32_t nout, const std::string& amount, const std::string& pk);
    CreateInscriptionBuilder& Data(const std::string& content_type, const std::string& hex_data);
    CreateInscriptionBuilder& DestinationPubKey(const std::string& pk);
    CreateInscriptionBuilder& AddToCollection(const std::string& collection_id, const string& utxo_txid, uint32_t utxo_nout, const std::string& utxo_amount);

    std::string getIntermediateTaprootSK() const
    { return hex(m_inscribe_taproot_sk.value()); }

    std::string GetInscribeScriptPubKey() const
    { return hex(m_inscribe_script_pk.value()); }

    std::string GetInscribeScriptSig() const
    { return hex(m_inscribe_script_sig.value()); }

    std::string GetInscribeInternaltPubKey() const;

    void SignCommit(uint32_t n, const std::string& sk, const std::string& inscribe_script_pk);
    void SignCollection(const std::string& sk);
    void SignInscription(const std::string& insribe_script_sk);

    std::string GetMinFundingAmount() const override;

    std::vector<std::string> RawTransactions() const;

    std::string Serialize() const;
    void Deserialize(const std::string& data);

};

} // inscribeit

