#pragma once

#include <algorithm>
#include <stdexcept>
#include <sstream>
#include <concepts>

namespace cex {

template <typename C>
class stream {
public:
    typedef C container_type;
    typedef typename container_type::value_type value_type;
    typedef std::iter_difference_t<typename container_type::iterator> difference_type;
    typedef typename container_type::size_type size_type;
private:
    typedef typename container_type::iterator iterator;
    typedef typename container_type::const_iterator const_iterator;

private:
    container_type m_container;
    iterator m_read_it;
public:
    stream() : m_container(), m_read_it(m_container.begin()) {}
    explicit stream(container_type&& container) : m_container(std::move(container)), m_read_it(m_container.cbegin()) {}

    void put(const value_type& element)
    { m_container.emplace_back(element); }

    stream& write(const value_type* p, size_type count)
    { m_container.insert(m_container.end(), p, p + count); return *this; }


    template<typename V>
    stream& write(const V& elements)
    { m_container.insert(m_container.end(), elements.begin(), elements.end()); return *this;}

    const value_type& get()
    { return *m_read_it++; }

    stream& read(value_type* p, size_type count)
    {
        if (m_container.end() - m_read_it < count) throw std::range_error("Not enough data to read");

        iterator end_it = m_read_it + count;
        std::transform(m_read_it, end_it, p, [&](const auto& v){ return v; });
        m_read_it = end_it;
        return *this;
    }

    template <typename V>
    stream& read(const V& elements)
    {
        if (m_container.end() - m_read_it < elements.size()) throw std::range_error("Not enough data to read");

        iterator end_it = m_read_it + elements.size();
        std::transform(m_read_it, end_it, elements.begin(), [&](const auto& v){ return v; });
        m_read_it = end_it;
        return *this;
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
    { m_container.clear(); m_read_it = m_container.begin(); }

    void rewind(difference_type n = 0)
    {
        if (!n) {
            m_read_it = m_container.begin();
        } else {
            if (m_read_it - m_container.begin() < n) {
                std::stringstream errmsg;
                errmsg << "Not enough space to rewind: space (" << (m_read_it - m_container.begin()) << "), arg(" << n << ")";
                throw std::range_error(errmsg.str());
            }
            std::advance(m_read_it, -n);
        }
    }

    void expand(difference_type n)
    {
        if (m_container.end() - m_read_it < n) {
            std::stringstream errmsg("Not enough size to expand: ");
            errmsg << n;
            throw std::range_error(errmsg.str());
        }
        std::advance(m_read_it, n);
    }

    difference_type position() const
    { return m_read_it - m_container.cbegin(); }

    const value_type* read_pointer() const
    { return &(*m_read_it); }

    difference_type remains() const
    { return m_container.end() - m_read_it; }

    const_iterator begin() const
    { return m_container.begin(); }

    const_iterator end() const
    { return m_container.end(); }

    const value_type* data() const
    { return m_container.data(); }

    size_type size() const
    { return m_container.size(); }
};

template<typename V>
stream<V>& operator << (stream<V>& s, const std::integral auto& arg)
{
    static_assert(std::is_integral_v<typename stream<V>::value_type>);

    auto v = arg;
    const size_t shift_step = sizeof(typename stream<V>::value_type) * 8;
    auto mask = v;
    mask = (1 << shift_step) - 1;

    if (sizeof(v) > sizeof(typename stream<V>::value_type)) {
        for (size_t bit_shift = sizeof(v) * 8 - shift_step; bit_shift; bit_shift -= shift_step) {
            s.put(static_cast<typename stream<V>::value_type>((v >> bit_shift) & mask));
        }
    }
    s.put(static_cast<typename stream<V>::value_type>(v & mask));
    return s;
}

template<typename V>
stream<V>& operator >> (stream<V>& s, std::integral auto& res)
{
    static_assert(std::is_integral_v<typename stream<V>::value_type>);

    auto v = res;

    const size_t shift_step = sizeof(typename stream<V>::value_type) * 8;
    auto mask = v;
    mask = (1 << shift_step) - 1;
    size_t steps = sizeof(v) / sizeof(typename stream<V>::value_type);

    v = 0;
    for (size_t i = 0; i < steps; ++i) {
        v = v << shift_step;
        auto a = s.get();
        v |= (a & mask);
    }
    res = v;
    return s;
}

}