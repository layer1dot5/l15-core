#include "contract_builder.hpp"
#include "interpreter.h"
#include "script_merkle_tree.hpp"
#include "channel_keys.hpp"

namespace l15::inscribeit {

const std::string ContractBuilder::name_contract_type = "contract_type";
const std::string ContractBuilder::name_params = "params";
const std::string ContractBuilder::name_version = "protocol_version";
const std::string ContractBuilder::name_mining_fee_rate = "mining_fee_rate";

CAmount ContractBuilder::CalculateWholeFee() const {
    auto txs = GetTransactions();
    return std::accumulate(txs.begin(), txs.end(), CAmount(0), [this](CAmount sum, const std::pair<CAmount,CMutableTransaction> &tx) -> CAmount {
        return sum += l15::CalculateTxFee(tx.first, tx.second);
    });
}

std::string ContractBuilder::GetWholeFee() {
    return FormatAmount(CalculateWholeFee());
}

void ContractBuilder::VerifyTxSignature(const xonly_pubkey& pk, const signature& sig, const CMutableTransaction& tx, uint32_t nin, std::vector<CTxOut>&& spent_outputs, const CScript& spend_script)
{
    if (sig.size() != 64 && sig.size() != 65) throw SignatureError("sig size");

    uint256 sighash;
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::move(spent_outputs), true);

    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false; // Only support annex-less signing for now.

    if(!spend_script.empty()) {
        execdata.m_codeseparator_pos_init = true;
        execdata.m_codeseparator_pos = 0xFFFFFFFF; // Only support non-OP_CODESEPARATOR BIP342 signing for now.
        execdata.m_tapleaf_hash_init = true;
        execdata.m_tapleaf_hash = TapLeafHash(spend_script);
    }

    uint8_t hashtype = SIGHASH_DEFAULT;
    if (sig.size() == 65) {
        hashtype = sig.back();
        if (hashtype == SIGHASH_DEFAULT) {
            throw SignatureError("sighash type");
        }
    }

    SigVersion sigversion = spend_script.empty() ? SigVersion::TAPROOT : SigVersion::TAPSCRIPT;

    if (!SignatureHashSchnorr(sighash, execdata, tx, nin, hashtype, sigversion, txdata, MissingDataBehavior::FAIL)) {
        throw SignatureError("sighash");
    }
    if (!pk.verify(core::ChannelKeys::GetStaticSecp256k1Context(), sig, sighash)) {
        throw SignatureError("sig");
    }
}

} // inscribeit
