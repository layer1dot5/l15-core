#pragma once

#include <string>

#include "utils.hpp"
#include "common_error.hpp"

namespace l15::inscribeit {

class ContractError : public Error {
public:
    explicit ContractError(std::string&& details) : Error(move(details)) {}
    ~ContractError() override = default;

    const char* what() const noexcept override
    { return "ContractError"; }
};

class ContractTermMissing : public ContractError {
public:
    explicit ContractTermMissing(std::string&& details) : ContractError(move(details)) {}
    ~ContractTermMissing() override = default;

    const char* what() const noexcept override
    { return "ContractTermsMissing"; }
};

class ContractProtocolError : public ContractError {
public:
    explicit ContractProtocolError(std::string&& details) : ContractError(move(details)) {}
    ~ContractProtocolError() override = default;

    const char* what() const noexcept override
    { return "ContractProtocolError"; }
};

class ContractBuilder
{
public:
    static const std::string name_contract_type;
    static const std::string name_params;
    static const std::string name_version;
    static const std::string name_mining_fee_rate;

protected:
    std::shared_ptr<IBech32Coder> m_bech_coder;

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

    explicit ContractBuilder(const std::string& chain_mode)
    {
        if (chain_mode == "mainnet") {
            m_bech_coder = std::make_shared<Bech32Coder<IBech32Coder::ChainType::BTC, IBech32Coder::ChainMode::MAINNET>>();
        }
        else if (chain_mode == "testnet") {
            m_bech_coder = std::make_shared<Bech32Coder<IBech32Coder::ChainType::BTC, IBech32Coder::ChainMode::TESTNET>>();
        }
        else if (chain_mode == "regtest") {
            m_bech_coder = std::make_shared<Bech32Coder<IBech32Coder::ChainType::BTC, IBech32Coder::ChainMode::REGTEST>>();
        }
        else {
            throw std::invalid_argument(std::string("wrong chain mode: ") + chain_mode);
        }
    }

    virtual uint32_t GetProtocolVersion() const = 0;

    std::string GetMiningFeeRate() const { return FormatAmount(m_mining_fee_rate.value()); }
    void SetMiningFeeRate(std::string v) { m_mining_fee_rate = ParseAmount(v); }

    static void VerifyTxSignature(const xonly_pubkey& pk, const signature& sig, const CMutableTransaction& tx, uint32_t nin, std::vector<CTxOut>&& spent_outputs, const CScript& spend_script);


};

} // inscribeit

