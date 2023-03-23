#pragma once

#include <string>
#include <vector>
#include <optional>
#include <memory>

#include "univalue.h"

#include "common.hpp"
#include "utils.hpp"

namespace l15::inscribeit {

class CreateInscriptionBuilder {
    std::unique_ptr<IBech32Coder> m_bech_coder;

    std::optional<std::string> m_txid;
    std::optional<uint32_t> m_nout;
    std::optional<CAmount> m_amount;

    std::optional<CAmount> m_fee_rate;

    std::optional<std::string> m_content_type;
    std::optional<bytevector> m_data;

    std::optional<seckey> m_utxo_sk;
    std::optional<xonly_pubkey> m_utxo_pk; //taproot
    std::optional<signature> m_utxo_sig;

    //std::optional<seckey> m_inscribe_script_sk;
    std::optional<xonly_pubkey> m_insribe_script_pk;
    std::optional<signature> m_inscribe_script_sig;

    std::optional<seckey> m_inscribe_taproot_sk; // needed in case of a fallback scenario to return funds
    std::optional<xonly_pubkey> m_inscribe_int_pk; //taproot

    std::optional<seckey> m_destination_sk;
    std::optional<xonly_pubkey> m_destination_pk;

    std::optional<CTransaction> mFundingTx;
    std::optional<CTransaction> mGenesisTx;

    void CheckBuildArgs() const;
    void CheckRestoreArgs(const UniValue& params) const;

    void RestoreTransactions();

public:
    explicit CreateInscriptionBuilder(const std::string& chain_mode);
    CreateInscriptionBuilder& UTXO(const std::string& txid, uint32_t nout, const std::string& amount);
    CreateInscriptionBuilder& Data(const std::string& content_type, const std::string& hex_data);
    CreateInscriptionBuilder& FeeRate(const std::string& rate);
    CreateInscriptionBuilder& PrivKeys(const std::string& utxo_sk, const std::string& destination_sk);

    std::string IntermediateTaprootPrivKey() const
    { return hex(*m_inscribe_taproot_sk); }


    void Build();

    std::vector<std::string> RawTransactions() const;

    std::string Serialize() const;
    void Deserialize(const std::string& data);

};

} // inscribeit

