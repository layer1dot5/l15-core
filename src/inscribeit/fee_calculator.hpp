#pragma once

#include <optional>

#include "amount.h"
#include "primitives/transaction.h"

#include "common_error.hpp"
#include "channel_keys.hpp"
#include "utils.hpp"

namespace l15::inscribeit {
/*
template <typename T, uint8_t recursion = 2>
class WithDummy;
*/
template <typename T>
class Dummy {
public:
    template<typename... _Args>
    explicit Dummy(_Args&&... args) {
        m_dummyObjPtr = std::make_shared<T>(args...);
    }
    std::shared_ptr<T> getDummy() const {
        return m_dummyObjPtr;
    }
protected:
    virtual CAmount getFee(CAmount fee_rate, const CMutableTransaction& tx) const { return l15::CalculateTxFee(fee_rate, tx); }
    virtual CAmount getFee(CAmount fee_rate, const CMutableTransaction& sampleTx, const CMutableTransaction& actualTx) { return getFee(fee_rate, sampleTx); }
private:
    std::shared_ptr<T> m_dummyObjPtr;

};

template <typename T>
class FeeCalculator: public Dummy<T> {
public:
    FeeCalculator(const FeeCalculator<T> &other) = default;
    FeeCalculator(FeeCalculator<T> &&other) = default;

    virtual ~FeeCalculator() = default;
};

/*
template <typename T, uint8_t recursion>
class WithDummy {
public:
    template<typename... _Args>
    WithDummy(_Args&&... args): m_dummy() {
        //initDummy(args...);
    }

    template<uint8_t newRecursion = recursion - 1, typename... _Args>
    void initDummy(_Args&&... args) {
        if (recursion > 0) {
            m_dummy = std::make_shared<Dummy<T, newRecursion - 1>>(args...);
            m_dummy->fillDummySettings();
        }
    }
protected:
    Dummy<T>::Ptr getDummy() { return m_dummy; }
private:
    Dummy<T, recursion-1>::Ptr m_dummy;
};

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
/*
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
*/

} // namespace l15::inscribeit
