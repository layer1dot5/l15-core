#include "fee_calculator.hpp"

#include "consensus.h"

#include "channel_keys.hpp"
#include "swap_inscription.hpp"

namespace l15::inscribeit {

CAmount TransactionFee::Calculate(const std::string &miningFeeRate) {
    auto rate = ParseAmount(miningFeeRate);
    if (rate != m_feeRate) {
        m_feeRate = rate;
        m_cachedFee = GetFee();
    }
    return m_cachedFee;
}

CAmount FeeCalculator::getFee(const std::string &miningFeeRate,
                              const l15::inscribeit::TransactionKind kind) {
    auto fee = m_transactionFees[kind];
    if (!fee) {
        throw l15::TransactionError("undefined transaction kind for fee estimation");
    }
    return (*fee)(miningFeeRate);
}

namespace fees {

std::string samplePubKey = "03e52e1c15ed350d42f7cda2e0a96b3ee8cb86b9e9d5f6a5e5c8c6b5f222a97de6";
std::string samplePrivKey = "9d6f1f1686e5c5f2b6a752a6f97b135c5a6a8a6d9bbd421ec58dfc1dc85d68a6";
uint32_t sampleNOutput = 0;
std::string sampleOutput = "1JzTLxWJL9Axy4QbYcZm3a8KjFCDNXmzS4";
int sampleFundOut;

CAmount FundsCommit::GetFee() {
    auto fee_rate = getFeeRate();

    SwapInscriptionBuilder builder("regtest", "0.1", "0.01");

    l15::core::ChannelKeys swap_script_key_A;
    l15::core::ChannelKeys swap_script_key_B;
    l15::core::ChannelKeys swap_script_key_M;
    l15::core::ChannelKeys ord_utxo_key;
    l15::core::ChannelKeys funds_utxo_key;

    seckey preimage = l15::core::ChannelKeys::GetStrongRandomKey();
    bytevector swap_hash(32);
    CHash256().Write(preimage).Finalize(swap_hash);

    builder.SetOrdCommitMiningFeeRate(fee_rate);
    builder.SetMiningFeeRate(fee_rate);

    builder.SetSwapHash(hex(swap_hash));
    builder.SetSwapScriptPubKeyB(hex(swap_script_key_B.GetLocalPubKey()));
    builder.SetSwapScriptPubKeyM(hex(swap_script_key_M.GetLocalPubKey()));
    builder.SetSwapScriptPubKeyA(hex(swap_script_key_A.GetLocalPubKey()));

    builder.SetOrdUtxoTxId(hex(sampleOutput));
    builder.SetOrdUtxoNOut(sampleNOutput);
    builder.SetOrdUtxoAmount("1");

    builder.SignOrdCommitment(hex(ord_utxo_key.GetLocalPrivKey()));
    builder.SignOrdSwap(hex(swap_script_key_A.GetLocalPrivKey()));

    builder.SetFundsUtxoTxId(hex(sampleOutput));
    builder.SetFundsUtxoNOut(sampleNOutput);
    builder.SetFundsUtxoAmount("1");

    builder.SignFundsCommitment(hex(funds_utxo_key.GetLocalPrivKey()));

    builder.CheckContractTerms(SwapInscriptionBuilder::FundsCommitSig);
    auto tx = builder.GetFundsCommitTx();

    return CalculateTxFee(fee_rate, tx);
}

} // namespace l15::inscribeit::fees

} // namespace l15::inscribeit
