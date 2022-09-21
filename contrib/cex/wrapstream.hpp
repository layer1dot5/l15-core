#pragma once

#include <algorithm>
#include <stdexcept>
#include <sstream>

namespace cex {

template <typename C>
class stream {
public:
    typedef C container_type;
    typedef typename container_type::value_type value_type;
    typedef std::iter_difference_t<typename container_type::const_iterator> difference_type;
private:
    typedef typename container_type::const_iterator container_iterator;

private:
    container_type m_container;
    container_iterator m_read_it;
public:
    stream() : m_container(), m_read_it(m_container.cbegin()) {}
    explicit stream(container_type&& container) : m_container(std::move(container)), m_read_it(m_container.cbegin()) {}

    template<typename V>
    void write(V& elements)
    { m_container.insert(m_container.end(), elements.begin(), elements.end()); }

    template <typename V>
    void read(V elements)
    {
        if (m_container.end() - m_read_it < elements.size()) throw std::range_error("Not enough data to read");

        container_iterator end_it = m_read_it + elements.size();
        std::transform(m_read_it, end_it, elements.begin(), [&](const auto& v){ return v; });
        m_read_it = end_it;
    }

    template <class I>
    void append(I begin, I end)
    {
        auto it = m_container.end();
        m_container.resize(m_container.size() + (end - begin));
        std::transform(begin, end, it, [&](const auto& v){ return static_cast<value_type>(v); });
    }

    bool empty() const
    { return m_container.empty(); }

    void clear()
    { m_container.clear(); m_read_it = m_container.cbegin(); }

    void rewind(difference_type n = 0)
    {
        if (!n) {
            m_read_it = m_container.cbegin();
        } else {
            if (m_read_it - m_container.cbegin() > n) {
                std::stringstream errmsg("Not enough size to rewind: ");
                errmsg << n;
                throw std::range_error(errmsg.str());
            }
            std::advance(m_read_it, -n);
        }
    }
};

}