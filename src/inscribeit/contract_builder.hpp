#pragma once

#include <string>

#include "utils.hpp"
#include "contract_error.hpp"

namespace l15::inscribeit {


class ContractBuilder
{
public:
    static const std::string name_contract_type;
    static const std::string name_params;
    static const std::string name_version;
    static const std::string name_mining_fee_rate;

protected:
    std::optional<CAmount> m_mining_fee_rate;

    virtual CAmount CalculateWholeFee() const;

public:
    ContractBuilder() = default;
    ContractBuilder(const ContractBuilder&) = default;
    ContractBuilder(ContractBuilder&& ) noexcept = default;

    ContractBuilder& operator=(const ContractBuilder& ) = default;
    ContractBuilder& operator=(ContractBuilder&& ) noexcept = default;

    virtual std::vector<std::pair<CAmount,CMutableTransaction>> GetTransactions() const = 0;
    virtual std::string GetMinFundingAmount() const = 0;

    virtual uint32_t GetProtocolVersion() const = 0;

    std::string GetMiningFeeRate() const { return FormatAmount(m_mining_fee_rate.value()); }
    void SetMiningFeeRate(const std::string& v) { m_mining_fee_rate = ParseAmount(v); }

    static void VerifyTxSignature(const xonly_pubkey& pk, const signature& sig, const CMutableTransaction& tx, uint32_t nin, std::vector<CTxOut>&& spent_outputs, const CScript& spend_script);


};

} // inscribeit

