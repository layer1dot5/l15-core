#pragma once

#include <vector>
#include <stdexcept>
#include <compare>

#include "cex_defs.hpp"

namespace cex {

template<typename Tp, size_t SIZE, typename Alloc = std::allocator<Tp> >
class fixsize_vector : protected std::vector<Tp, Alloc> {
public:

    typedef std::vector<Tp, Alloc> base;
    typedef typename base::value_type		value_type;
    typedef typename base::pointer			pointer;
    typedef typename base::const_pointer	const_pointer;
    typedef typename base::reference		reference;
    typedef typename base::const_reference	const_reference;
    typedef typename base::iterator        iterator;
    typedef typename base::const_iterator const_iterator;
    typedef typename base::const_reverse_iterator const_reverse_iterator;
    typedef typename base::const_reverse_iterator reverse_iterator;
    typedef typename base::size_type       size_type;
    typedef typename base::difference_type difference_type;
    typedef typename base::allocator_type  allocator_type;

private:
    template <typename T>
    const T& check_size(const T& b) {
        if (b.size() != SIZE) throw std::out_of_range("Wrong size");
        return b;
    }

    template <typename T>
    T&& check_resize(T&& b) noexcept {
        if (b.size() != SIZE) b.resize(SIZE);
        return std::move(b);
    }

public:


    fixsize_vector() CEXCXX_NOEXCEPT : base(SIZE) {}
    explicit fixsize_vector(const allocator_type& a) CEXCXX_NOEXCEPT : base(SIZE, a) {}
    explicit fixsize_vector(const value_type& v) CEXCXX_NOEXCEPT : base(SIZE, v) {}
    fixsize_vector(const value_type& v, const allocator_type& a) CEXCXX_NOEXCEPT : base(SIZE, v, a) {}

    fixsize_vector(const fixsize_vector& v) : base(v) {}
    fixsize_vector(fixsize_vector&& v) CEXCXX_NOEXCEPT : base(std::move(v)) {}

    explicit fixsize_vector(const base& v) : base(check_size(v)) {}
    explicit fixsize_vector(base&& v) CEXCXX_NOEXCEPT : base(check_resize(std::move(v))) {}

    fixsize_vector(const fixsize_vector& v, const allocator_type& a) : base(v, a) {}
    fixsize_vector(fixsize_vector&& v, const allocator_type& a) : base(std::move(v), a) {}

    fixsize_vector(std::initializer_list<value_type> l, const allocator_type& a = allocator_type()) : base(check_size(l)) {}

    template<typename I, typename = std::_RequireInputIter<I>>
    fixsize_vector(I f, I l, const allocator_type& a = allocator_type()) : base(SIZE, a)
    { assign(f, l); }

    ~fixsize_vector() CEXCXX_NOEXCEPT = default;

    fixsize_vector& operator=(const fixsize_vector& x) { base::operator=(x); return *this; }
    fixsize_vector& operator=(fixsize_vector&& x) CEXCXX_NOEXCEPT { base::operator=(std::move(x)); return *this; }

    fixsize_vector& operator=(const base& x) { base::operator=(check_size(x)); return *this; }
    fixsize_vector& operator=(base&& x) CEXCXX_NOEXCEPT { base::operator=(check_resize(std::move(x))); return *this; }

    fixsize_vector& operator=(std::initializer_list<value_type> l) { base::operator=(check_size(l)); return *this; }

    void assign(const value_type& v) { assign(SIZE, v); }
    void assign(std::initializer_list<value_type> l) { base::assign(check_size(l)); }

    template<typename I, typename = std::_RequireInputIter<I>>
    void assign(I f, I l)
    {
        if (std::distance(f, l) != SIZE) throw std::out_of_range("Wrong size");
        base::assign(f, l);
    }

    void swap(base& x) { base::swap(check_size(x)); }

    explicit operator base&(){ return reinterpret_cast<base&>(*this); }
    explicit operator const base&() const { return reinterpret_cast<const base&>(*this); }

    using base::begin;
    using base::cbegin;
    using base::rbegin;
    using base::crbegin;

    using base::end;
    using base::cend;
    using base::rend;
    using base::crend;

    using base::size;
    using base::max_size;

    using base::capacity;

    using base::operator[];
    using base::at;

    using base::front;
    using base::back;

    using base::data;
};

template< class T, size_t SIZE1, size_t SIZE2, class A1, class A2 >
CEXCXX20_CONSTEXPR bool operator==(const fixsize_vector<T, SIZE1, A1>& x1, const fixsize_vector<T, SIZE2, A2>& x2)
{ return reinterpret_cast<const std::vector<T, A1>&>(x1) == reinterpret_cast<const std::vector<T, A2>&>(x2); }

#if __cplusplus >= 202002L

template< class T, size_t SIZE1, /*size_t SIZE2, */class A1/*, class A2*/ >
constexpr std::strong_ordering operator<=>(const fixsize_vector<T, SIZE1, A1>& x1, const fixsize_vector<T, SIZE1, A1>& x2)
{ return reinterpret_cast<const std::vector<T, A1>&>(x1) <=> reinterpret_cast<const std::vector<T, A1>&>(x2); }

#else

template< class T, size_t SIZE1, size_t SIZE2, class A1, class A2 >
bool operator<(const fixsize_vector<T, SIZE1, A1>& x1, const fixsize_vector<T, SIZE2, A2>& x2)
{ return reinterpret_cast<const std::vector<T, A1>&>(x1) < reinterpret_cast<const std::vector<T, A2>&>(x2); }

#endif


//template< class T, size_t SIZE, class A1, class A2 >
//bool operator==(const fixsize_vector<T, SIZE, A1>& x1, const std::vector<T, A2>& x2)
//{ return reinterpret_cast<const std::vector<T, A1>&>(x1) == x2; }
//
//template< class T, size_t SIZE, class A1, class A2 >
//bool operator==(const std::vector<T, A1>& x1, const fixsize_vector<T, SIZE, A2>& x2)
//{ return x1 == reinterpret_cast<const std::vector<T, A2>&>(x2); }

template <class STREAM, class T, size_t SIZE, class A>
STREAM& operator << (STREAM& s, const fixsize_vector<T, SIZE, A>& x)
{ return s.write(x.data(), SIZE); }

template <class STREAM, class T, size_t SIZE, class A>
STREAM& operator >> (STREAM& s, fixsize_vector<T, SIZE, A>& x)
{ return s.read(x.data(), SIZE); }

}
