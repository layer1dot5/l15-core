#include "fee_calculator.hpp"

#include "consensus.h"

#include "swap_inscription.hpp"

namespace l15::inscribeit {

CAmount TransactionFee::Calculate(TransactionKind kind, const std::string &miningFeeRate) {
    auto rate = ParseAmount(miningFeeRate);
    if (rate != m_feeRate) {
        m_feeRate = rate;
        m_cachedFee = GetFee(kind);
    }
    return GetFee(kind);
}

FeeCalculator::FeeCalculator() {
    auto ptr = std::make_shared<fees::OrdinalTransactions>();
    m_transactionFees.insert({TransactionKind::FundsCommit, ptr});
    m_transactionFees.insert({TransactionKind::OrdinalCommit, ptr});
    m_transactionFees.insert({TransactionKind::OrdinalSwap, ptr});
    m_transactionFees.insert({TransactionKind::OrdinalTransfer, ptr});
};

CAmount FeeCalculator::getFee(const std::string &miningFeeRate,
                              const l15::inscribeit::TransactionKind kind) {
    auto fee = m_transactionFees[kind];
    if (!fee) {
        throw l15::TransactionError("undefined transaction kind for fee estimation");
    }
    return (*fee)(kind, miningFeeRate);
}

namespace fees {

uint32_t sampleNOutput = 0;
std::string sampleOutput = "0000000000000000000000000000000000000000000000000000000000000000";

CAmount OrdinalTransactions::Calculate(TransactionKind kind, const std::string &miningFeeRate) {
    auto rate = ParseAmount(miningFeeRate);
    if (rate != m_feeRate) {
        m_feeRate = rate;
    }
    return GetFee(kind);
}

CAmount OrdinalTransactions::GetFee(TransactionKind kind) {
    auto fee_rate = getFeeRate();

    switch(kind) {
        case TransactionKind::FundsCommit: return CalculateTxFee(fee_rate, m_fundsCommit);
        case TransactionKind::OrdinalCommit: return CalculateTxFee(fee_rate, m_ordCommit);
        case TransactionKind::OrdinalSwap: return CalculateTxFee(fee_rate, m_ordSwap);
        case TransactionKind::OrdinalTransfer: return CalculateTxFee(fee_rate, m_ordTransfer);
    }

    throw l15::TransactionError("unknown transaction type for estimation");
}

void OrdinalTransactions::createTransactions() {
    SwapInscriptionBuilder builder("regtest", "0.1", "0.01");


    builder.SetOrdCommitMiningFeeRate("0.00001");
    builder.SetMiningFeeRate("0.00001");

    builder.SetSwapScriptPubKeyB(hex(m_swapScriptKeyB.GetLocalPubKey()));
    builder.SetSwapScriptPubKeyM(hex(m_swapScriptKeyM.GetLocalPubKey()));
    builder.SetSwapScriptPubKeyA(hex(m_swapScriptKeyA.GetLocalPubKey()));

    builder.SetOrdUtxoTxId(sampleOutput);
    builder.SetOrdUtxoNOut(sampleNOutput);
    builder.SetOrdUtxoAmount("1");

    builder.SignOrdCommitment(hex(m_ordUtxoKey.GetLocalPrivKey()));
    builder.SignOrdSwap(hex(m_swapScriptKeyA.GetLocalPrivKey()));

    builder.SetFundsUtxoTxId(sampleOutput);
    builder.SetFundsUtxoNOut(sampleNOutput);
    builder.SetFundsUtxoAmount("1");

    builder.SignFundsCommitment(hex(m_fundsUtxoKey.GetLocalPrivKey()));

    m_fundsCommit = builder.GetFundsCommitTx();
    m_ordCommit = builder.GetOrdCommitTx();

    builder.MarketSignOrdPayoffTx(hex(m_swapScriptKeyM.GetLocalPrivKey()));
    builder.SignFundsSwap(hex(m_swapScriptKeyB.GetLocalPrivKey()));

    m_ordSwap = builder.GetSwapTx();
    m_ordTransfer = builder.GetPayoffTx();
}

} // namespace l15::inscribeit::fees

} // namespace l15::inscribeit