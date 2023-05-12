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
    std::list<Transfer> m_xtra_utxo;

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

    mutable bool mInscriptionScriptHasCollectionId = false;
    mutable std::optional<CScript> mInscriptionScript;
    mutable std::optional<CMutableTransaction> mCommitTx;
    mutable std::optional<CMutableTransaction> mGenesisTx;

private:
    void CheckBuildArgs() const;

    void RestoreTransactions();

    const CScript& GetInscriptionScript() const;
    std::vector<CTxOut> GetGenesisTxSpends() const;
    CMutableTransaction PrepaireGenesisTx(bool to_sign);

    std::vector<std::pair<CAmount,CMutableTransaction>> GetTransactions() const override;

    CMutableTransaction CreateCommitTxTemplate() const;
    CMutableTransaction CreateGenesisTxTemplate() const;

    const CMutableTransaction& CommitTx() const;

public:

    static const std::string name_ord_amount;
    static const std::string name_utxo;
    static const std::string name_xtra_utxo;
    static const std::string name_txid;
    static const std::string name_nout;
    static const std::string name_amount;
    static const std::string name_pk;
    static const std::string name_sig;
    static const std::string name_content_type;
    static const std::string name_content;
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

    const std::string& GetContentType() const { return *m_content_type; }
    std::string GetContent() const { return l15::hex(m_content.value()); }
    std::string GetDestinationPubKey() const { return l15::hex(m_destination_pk.value()); }

    std::string GetIntermediateSecKey() const { return l15::hex(m_inscribe_taproot_sk.value()); }

    CreateInscriptionBuilder& MiningFeeRate(const std::string& rate);
    CreateInscriptionBuilder& AddUTXO(const std::string &txid, uint32_t nout, const std::string& amount, const std::string& pk);
    CreateInscriptionBuilder& Data(const std::string& content_type, const std::string& hex_data);
    CreateInscriptionBuilder& DestinationPubKey(const std::string& pk);
    CreateInscriptionBuilder& AddToCollection(const std::string& collection_id, const std::string& utxo_txid, uint32_t utxo_nout, const std::string& utxo_amount);
    CreateInscriptionBuilder& AddFundMiningFee(const std::string &txid, uint32_t nout, const std::string& amount, const std::string& pk);

    std::string getIntermediateTaprootSK() const
    { return hex(m_inscribe_taproot_sk.value()); }

    std::string GetInscribeScriptPubKey() const
    { return hex(m_inscribe_script_pk.value()); }

    std::string GetInscribeScriptSig() const
    { return hex(m_inscribe_script_sig.value()); }

    std::string GetInscribeInternalPubKey() const;

    std::string GetGenesisTxMiningFee() const;

    void SignCommit(uint32_t n, const std::string& sk, const std::string& inscribe_script_pk);
    void SignCollection(const std::string& sk);
    void SignInscription(const std::string& insribe_script_sk);
    void SignFundMiningFee(uint32_t n, const std::string& sk);

    std::string GetMinFundingAmount() const override;

    std::vector<std::string> RawTransactions() const;

    std::string Serialize() const;
    void Deserialize(const std::string& data);

};

} // inscribeit

