#pragma once

#include <memory>

namespace cex {

template<typename T, typename E, const char * const M>
class safe_ptr
{
    std::weak_ptr<T> m_ptr;
public:

    safe_ptr() noexcept = delete;
    safe_ptr(const safe_ptr& ) = default;
    safe_ptr(safe_ptr&&) noexcept = default;

    safe_ptr(std::weak_ptr<T> ptr) : m_ptr(move(ptr)) {}
    safe_ptr(std::shared_ptr<T> ptr) : m_ptr(move(ptr)) {}

    safe_ptr& operator=(const safe_ptr&) = default;
    safe_ptr& operator=(safe_ptr&&) = default;

    std::shared_ptr<T> lock() const
    {
        auto p = m_ptr.lock();
        if (p) return p;
        else throw E(M);
    }

    const std::weak_ptr<T>& ref() const
    { return m_ptr; }
};

}