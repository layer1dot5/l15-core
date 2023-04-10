#pragma once

#include <optional>
#include "amount.h"
#include "primitives/transaction.h"
#include "common_error.hpp"

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

    CAmount operator() (const std::string &miningFeeRate) {
        if (m_isTransactionObligatory) {
            throw TransactionError("No transaction specified for mining fee calculator, but it is strongly required for this type of transactions");
        }
        return Calculate(miningFeeRate);
    }

    CAmount operator() (const std::string &miningFeeRate, const CTransaction &tx) {
        return Calculate(miningFeeRate, tx);
    }
protected:
    CAmount getFeeRate() const { return m_feeRate; }
    virtual CAmount Calculate(const std::string &miningFeeRate);
    virtual CAmount Calculate(const std::string &miningFeeRate, const CTransaction &tx) {
        return Calculate(miningFeeRate);
    }
    virtual std::optional<TransactionError> Check(const CTransaction &tx) const {return {}; };

    virtual CAmount GetFee() = 0;

    CAmount m_cachedFee = 0;
private:
    bool m_isTransactionObligatory = false;
    CAmount m_feeRate = 0;
};

namespace fees {

class FundsCommit : public TransactionFee {
public:
    FundsCommit(): TransactionFee(false) {}
    FundsCommit(const FundsCommit &other) = default;
    FundsCommit(FundsCommit &&other) = default;

    ~FundsCommit() override = default;
protected:
    CAmount GetFee() override;
};

}

class FeeCalculator {
public:
    FeeCalculator() {
        m_transactionFees.insert({TransactionKind::FundsCommit, std::make_shared<fees::FundsCommit>()});
    };
    FeeCalculator(const FeeCalculator &calculator) = default;
    FeeCalculator(FeeCalculator &&calculator) = default;

    CAmount getFee(const std::string &miningFeeRate, const TransactionKind kind);
    //CAmount getFee(const std::string &miningFeeRate, const TransactionKind kind, const CTransaction &tx);
private:
    std::map<TransactionKind, TransactionFee::Ptr> m_transactionFees;
};


} // namespace l15::inscribeit
