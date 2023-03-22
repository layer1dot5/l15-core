#pragma once

#include <string>
#include <vector>
#include <optional>
#include <memory>

#include "common.hpp"
#include "utils.hpp"

namespace l15::inscribeit {

class CreateInscriptionBuilder {
    std::unique_ptr<IBech32Coder> m_bech_coder;

    std::string m_txid;
    uint32_t m_nout;
    CAmount m_amount;

    CAmount m_fee_rate;

    std::string m_content_type;
    bytevector m_data;

    std::optional<l15::xonly_pubkey> m_destination_pk;

    std::optional<seckey> m_utxo_sk;
    std::optional<seckey> m_funding_sk;
    std::optional<seckey> m_genesys_sk;

    std::optional<l15::xonly_pubkey> m_utxo_pk;
    std::optional<signature> m_funding_sig;

    std::optional<l15::xonly_pubkey> m_funding_pk;
    std::optional<signature> m_genesys_sig;

public:
    explicit CreateInscriptionBuilder(const std::string& chain_mode);
    CreateInscriptionBuilder& UTXO(const std::string& txid, uint32_t nout, const std::string amount);
    CreateInscriptionBuilder& Data(const std::string& content_type, const std::string& hex_data);
    CreateInscriptionBuilder& DestinationAddress(const std::string& addr);
    CreateInscriptionBuilder& DestinationPK(const std::string& pubkey);
    CreateInscriptionBuilder& FeeRate(const std::string& rate);
    CreateInscriptionBuilder& PrivKeys(const std::string& utxo_key, const std::string& funding_key, const std::string& genesys_key);
    CreateInscriptionBuilder& FundingSignature(const l15::xonly_pubkey& utxo_pk, const std::string& funding_sig);
    CreateInscriptionBuilder& GenesysSignature(const l15::xonly_pubkey& funding_pk, const std::string& genesys_sig);

    std::vector<std::string> MakeRawTransactions();
    std::vector<std::string> MakeSignatures() const;

};

} // inscribeit

