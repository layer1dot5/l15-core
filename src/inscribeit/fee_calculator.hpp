#pragma once

#include <optional>

#include "amount.h"
#include "primitives/transaction.h"

#include "common_error.hpp"
#include "channel_keys.hpp"
#include "utils.hpp"

namespace l15::inscribeit {

class CanBeDummy {
public:
    CanBeDummy(bool isDummy = false) {m_isDummy = isDummy; }
    bool isDummy() const {return m_isDummy; }
    void setIsDummy(bool isDummy) { m_isDummy = isDummy; }
private:
    bool m_isDummy;
};

template <typename T>
class DummyContainer {
public:
    template<typename... _Args>
    explicit DummyContainer(_Args&&... args) {
        m_dummyObjPtr = std::make_shared<T>(args...);
        if(auto dummy = std::dynamic_pointer_cast<CanBeDummy>(m_dummyObjPtr)) {
            dummy->setIsDummy(true);
        }
    }

    std::shared_ptr<T> getDummy() const {
        return m_dummyObjPtr;
    }

protected:
    virtual CAmount getFee(CAmount fee_rate, const CMutableTransaction& tx) const { return l15::CalculateTxFee(fee_rate, tx); }
private:
    std::shared_ptr<T> m_dummyObjPtr;
};

template <typename T>
class FeeCalculator: public DummyContainer<T> {
public:
    FeeCalculator(const FeeCalculator<T> &other) = default;
    FeeCalculator(FeeCalculator<T> &&other) = default;

    virtual ~FeeCalculator() = default;
};

} // namespace l15::inscribeit
