#pragma once

#include <optional>

#include "amount.h"
#include "primitives/transaction.h"

#include "common_error.hpp"
#include "channel_keys.hpp"
#include "utils.hpp"

namespace l15::inscribeit {

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

} // namespace l15::inscribeit
