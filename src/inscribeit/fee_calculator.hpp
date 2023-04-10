#pragma once

#include <optional>

#include "amount.h"
#include "primitives/transaction.h"

#include "common_error.hpp"
#include "channel_keys.hpp"

namespace l15::inscribeit {

enum class TransactionKind {
    NotImplemented,
    FundsCommit,
    OrdinalCommit,
    OrdinalSwap,
    OrdinalTransfer
};

class TransactionFee {
public:
    typedef std::shared_ptr<TransactionFee> Ptr;
    explicit TransactionFee(bool isTransactionObligatory = false): m_isTransactionObligatory(isTransactionObligatory) { }

    virtual ~TransactionFee() = default;

    CAmount operator() (TransactionKind kind, const std::string &miningFeeRate) {
        if (m_isTransactionObligatory) {
            throw TransactionError("No transaction specified for mining fee calculator, but it is required for this type of transactions");
        }
        return Calculate(kind, miningFeeRate);
    }

    CAmount operator() (TransactionKind kind, const std::string &miningFeeRate, const CTransaction &tx) {
        return Calculate(kind, miningFeeRate, tx);
    }
protected:
    CAmount getFeeRate() const { return m_feeRate; }
    virtual CAmount Calculate(TransactionKind kind, const std::string &miningFeeRate);
    virtual CAmount Calculate(TransactionKind kind, const std::string &miningFeeRate, const CTransaction &tx) {
        return Calculate(kind, miningFeeRate);
    }
    virtual std::optional<TransactionError> Check(const CTransaction &tx) const {return {}; };

    virtual CAmount GetFee(TransactionKind kind) = 0;

    CAmount m_cachedFee = 0;
    CAmount m_feeRate = 0;
private:
    bool m_isTransactionObligatory = false;
};

namespace fees {

class OrdinalTransactions : public TransactionFee {
public:
    OrdinalTransactions(): TransactionFee(false) {
        createTransactions();
    }
    OrdinalTransactions(const OrdinalTransactions &other) = default;
    OrdinalTransactions(OrdinalTransactions &&other) = default;

    ~OrdinalTransactions() override = default;

    CAmount GetFee(TransactionKind kind) override;
protected:
    CAmount Calculate(TransactionKind kind, const std::string &miningFeeRate) override;

private:
    void createTransactions();

    l15::core::ChannelKeys m_swapScriptKeyA;
    l15::core::ChannelKeys m_swapScriptKeyB;
    l15::core::ChannelKeys m_swapScriptKeyM;
    l15::core::ChannelKeys m_ordUtxoKey;
    l15::core::ChannelKeys m_fundsUtxoKey;

    CMutableTransaction m_fundsCommit;
    CMutableTransaction m_ordCommit;
    CMutableTransaction m_ordSwap;
    CMutableTransaction m_ordTransfer;
};

}

class FeeCalculator {
public:
    FeeCalculator();
    FeeCalculator(const FeeCalculator &calculator) = default;
    FeeCalculator(FeeCalculator &&calculator) = default;

    CAmount getFee(const std::string &miningFeeRate, const TransactionKind kind);
    //CAmount getFee(const std::string &miningFeeRate, const TransactionKind kind, const CTransaction &tx);
private:
    std::map<TransactionKind, TransactionFee::Ptr> m_transactionFees;
};


} // namespace l15::inscribeit
