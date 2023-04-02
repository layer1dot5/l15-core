#pragma once

#include <string>

#include "utils.hpp"

namespace l15::inscribeit {

class ContractBuilder
{
public:
    static const std::string name_version;
    static const std::string name_mining_fee_rate;

protected:
    std::shared_ptr<IBech32Coder> m_bech_coder;

    std::optional<CAmount> m_mining_fee_rate;

public:
    ContractBuilder() = default;
    ContractBuilder(const ContractBuilder&) = default;
    ContractBuilder(ContractBuilder&& ) noexcept = default;

    ContractBuilder& operator=(const ContractBuilder& ) = default;
    ContractBuilder& operator=(ContractBuilder&& ) noexcept = default;

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
            throw std::invalid_argument(chain_mode);
        }
    }

    virtual uint32_t GetProtocolVersion() const = 0;

    std::string GetMiningFeeRate() const { return FormatAmount(m_mining_fee_rate.value()); }
    void SetMiningFeeRate(std::string v) { m_mining_fee_rate = ParseAmount(v); }


};

} // inscribeit

