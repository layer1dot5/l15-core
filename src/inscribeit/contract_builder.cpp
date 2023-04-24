#include "contract_builder.hpp"

namespace l15::inscribeit {

const std::string ContractBuilder::name_contract_type = "contract_type";
const std::string ContractBuilder::name_params = "params";
const std::string ContractBuilder::name_version = "protocol_version";
const std::string ContractBuilder::name_mining_fee_rate = "mining_fee_rate";

CAmount ContractBuilder::CalculateWholeFee() {
    auto txs = GetTransactions();
    return std::accumulate(txs.begin(), txs.end(), CAmount(0), [this](CAmount sum, const std::pair<CAmount,CMutableTransaction> &tx) -> CAmount {
        return sum += l15::CalculateTxFee(tx.first, tx.second);
    });
}

std::string ContractBuilder::GetWholeFee() {
    return FormatAmount(CalculateWholeFee());
}

} // inscribeit
