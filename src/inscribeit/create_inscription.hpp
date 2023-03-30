#pragma once

#include <string>
#include <sstream>
#include <vector>
#include <optional>
#include <memory>

#include "univalue.h"

#include "common.hpp"
#include "utils.hpp"

namespace l15::inscribeit {

    const std::string name_version("protocol_version");
    const std::string name_utxo_txid("utxo_txid");
    const std::string name_utxo_nout("utxo_nout");
    const std::string name_utxo_amount("utxo_amount");
    const std::string name_utxo_pk("utxo_pk");
    const std::string name_fee_rate("fee_rate");
    const std::string name_content_type("content_type");
    const std::string name_content("content");
    const std::string name_utxo_sig("utxo_sig");
    const std::string name_inscribe_script_pk("inscribe_script_pk");
    const std::string name_inscribe_int_pk("inscribe_int_pk");
    const std::string name_inscribe_sig("inscribe_sig");
    const std::string name_destination_pk("destination_pk");
    const std::string name_contract_type("contract_type");
    const std::string name_params("params");


    inline std::string FormatAmount(CAmount amount)
    {
        std::ostringstream str_amount;
        str_amount << (amount / COIN);
        CAmount rem = amount % COIN;
        if (rem) str_amount << '.' << rem;
        return str_amount.str();
    }

    inline CAmount CalculateOutputAmount(CAmount input_amount, CAmount fee_rate, size_t size)
    {
        return input_amount - static_cast<int64_t>(size) * fee_rate / 1024;
    }


    class CreateInscriptionBuilder {
        std::shared_ptr<IBech32Coder> m_bech_coder;

        static const uint32_t m_protocol_version = 1;

        std::optional<std::string> m_txid;
        std::optional<uint32_t> m_nout;
        std::optional<CAmount> m_amount;

        std::optional<CAmount> m_fee_rate;

        std::optional<std::string> m_content_type;
        std::optional<bytevector> m_content;

        //std::optional<seckey> m_utxo_sk;
        std::optional<xonly_pubkey> m_utxo_pk; //taproot
        std::optional<signature> m_utxo_sig;

        //std::optional<seckey> m_inscribe_script_sk;
        std::optional<xonly_pubkey> m_insribe_script_pk;
        std::optional<signature> m_inscribe_script_sig;

        std::optional<seckey> m_inscribe_taproot_sk; // needed in case of a fallback scenario to return funds
        std::optional<xonly_pubkey> m_inscribe_int_pk; //taproot

        //std::optional<seckey> m_destination_sk;
        std::optional<xonly_pubkey> m_destination_pk;

        std::optional<CMutableTransaction> mFundingTx;
        std::optional<CMutableTransaction> mGenesisTx;

        void CheckBuildArgs() const;
        void CheckRestoreArgs(const UniValue& params) const;

        void RestoreTransactions();

    public:
        CreateInscriptionBuilder() = default;
        CreateInscriptionBuilder(const CreateInscriptionBuilder&) = default;
        CreateInscriptionBuilder(CreateInscriptionBuilder&&) noexcept = default;

        CreateInscriptionBuilder& operator=(const CreateInscriptionBuilder&) = default;
        CreateInscriptionBuilder& operator=(CreateInscriptionBuilder&&) noexcept = default;

        explicit CreateInscriptionBuilder(const std::string& chain_mode);

        uint32_t GetProtocolVersion() const { return m_protocol_version; }

        std::string GetUtxoTxId() const { return m_txid.value(); }
        void SetUtxoTxId(std::string v) { m_txid = v; }

        uint32_t GetUtxoNOut() const { return m_nout.value(); }
        void SetUtxoNOut(uint32_t v) { m_nout = v; }

        std::string GetUtxoAmount() const { return FormatAmount( m_amount.value()); }
        void SetUtxoAmount(std::string v) { m_amount = ParseAmount(v); }

        std::string GetFeeRate() const { return FormatAmount( m_fee_rate.value()); }
        void SetFeeRate(std::string v) { m_fee_rate = ParseAmount(v); }

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

        std::vector<std::string> RawTransactions() const;

        std::string Serialize() const;
        void Deserialize(const std::string& data);

    };

} // inscribeit

