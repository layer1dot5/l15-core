#pragma once

#pragma clang diagnostic push
#pragma ide diagnostic ignored "HidingNonVirtualFunction"

#include <vector>
#include <iterator>
#include <stdexcept>

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
        return std::forward<T>(b);
    }

public:
    fixsize_vector() noexcept : base(SIZE) {}
    explicit fixsize_vector(const allocator_type& a) noexcept : base(SIZE, a) {}
    explicit fixsize_vector(const value_type& v) noexcept : base(SIZE, v) {}
    fixsize_vector(const value_type& v, const allocator_type& a) noexcept : base(SIZE, v, a) {}

    fixsize_vector(const fixsize_vector& v) : base(v) {}
    fixsize_vector(fixsize_vector&& v) noexcept : base(std::move(v)) {}

    fixsize_vector(const base& v) : base(check_size(v)) {}
    fixsize_vector(base&& v) noexcept : base(check_resize(std::move(v))) {}

    fixsize_vector(const fixsize_vector& v, const allocator_type& a) : base(v, a) {}
    fixsize_vector(fixsize_vector&& v, const allocator_type& a) : base(std::move(v), a) {}

    fixsize_vector(std::initializer_list<value_type> l, const allocator_type& a = allocator_type()) : base(check_size(l), a) {}

    template<std::input_iterator I>
    fixsize_vector(I f, I l, const allocator_type& a = allocator_type()) : base(SIZE, a)
    { assign(f, l); }

    ~fixsize_vector() noexcept = default;

    fixsize_vector& operator=(const fixsize_vector& x) { base::operator=(x); return *this; }

    template<typename AllocX>
    fixsize_vector& operator=(const fixsize_vector<value_type, SIZE, AllocX>& x)
    { assign(x.cbegin(), x.cend()); return *this; }

    fixsize_vector& operator=(fixsize_vector&& x) noexcept { base::operator=(std::move(x)); return *this; }

    fixsize_vector& operator=(const base& x) { base::operator=(check_size(x)); return *this; }

    template<typename AllocX>
    fixsize_vector& operator=(const std::vector<value_type, AllocX>& x)
    { assign(x.cbegin(), x.cend()); return *this; }

    fixsize_vector& operator=(base&& x) noexcept { base::operator=(check_resize(std::move(x))); return *this; }

    fixsize_vector& operator=(std::initializer_list<value_type> l) { base::operator=(check_size(l)); return *this; }

    void assign(const value_type& v) { assign(SIZE, v); }
    void assign(std::initializer_list<value_type> l) { base::assign(check_size(l)); }

    template<std::input_iterator I>
    void assign(I f, I l)
    {
        if (std::distance(f, l) != SIZE) throw std::out_of_range("Wrong size");
        base::assign(f, l);
    }

    base& as_vector() { return reinterpret_cast<base&>(*this); }
    const base& as_vector() const { return reinterpret_cast<base&>(*this); }

    void swap(base& x) { base::swap(check_size(x)); }

    void reserve(size_type n) { if (n != SIZE) throw std::out_of_range("Wrong size"); }
    void resize(size_type n) { if (n != SIZE) throw std::out_of_range("Wrong size"); }

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

template< class T, size_t SIZE1, size_t SIZE2, class Alloc >
bool operator==(const fixsize_vector<T, SIZE1, Alloc>& x1, const fixsize_vector<T, SIZE2, Alloc>& x2)
{ return reinterpret_cast<const std::vector<T, Alloc>&>(x1) == reinterpret_cast<const std::vector<T, Alloc>&>(x2); }

template< class T, size_t SIZE, class Alloc >
bool operator==(const fixsize_vector<T, SIZE, Alloc>& x1, const std::vector<T, Alloc>& x2)
{ return reinterpret_cast<const std::vector<T, Alloc>&>(x1) == x2; }

template< class T, size_t SIZE, class Alloc >
bool operator==(const std::vector<T, Alloc>& x1, const fixsize_vector<T, SIZE, Alloc>& x2)
{ return x1 == reinterpret_cast<const std::vector<T, Alloc>&>(x2); }

template <class STREAM, class T, size_t SIZE, class Alloc>
STREAM& operator << (STREAM& s, const fixsize_vector<T, SIZE, Alloc>& x)
{ return s.write(x.data(), SIZE); }

template <class STREAM, class T, size_t SIZE, class Alloc>
STREAM& operator >> (STREAM& s, fixsize_vector<T, SIZE, Alloc>& x)
{ return s.read(x.data(), SIZE); }

}

#pragma clang diagnostic pop
