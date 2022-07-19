#pragma once

#include <iterator>

#include "cex_defs.hpp"

namespace cex {

template<typename Container, typename Iter>
struct insert_reference {
    typedef std::iterator_traits<Iter>		traits_type;
    typedef typename traits_type::value_type value_type;

    Container& mContainer;
    Iter& mIt;

    insert_reference(Container& c, Iter& it) CEXCXX_NOEXCEPT
            : mContainer(c), mIt(it) {}

    insert_reference(const insert_reference& ) CEXCXX_NOEXCEPT = default;
    insert_reference(insert_reference&&) CEXCXX_NOEXCEPT = default;

    insert_reference& operator=(const value_type& v)
    { mIt = mContainer.insert(mIt, v); return *this; }

    insert_reference& operator=(value_type&& v)
    { mIt = mContainer.insert(mIt, std::move(v)); return *this; }

    insert_reference& operator=(value_type&& v) const
    { mIt = mContainer.insert(mIt, std::move(v)); return *this; }

#pragma clang diagnostic push
#pragma ide diagnostic ignored "google-explicit-constructor"
    operator value_type()
    { return *mIt; }

    operator value_type&() & CEXCXX_NOEXCEPT
    { return *mIt;}

    operator value_type const &() const CEXCXX_NOEXCEPT
    { return *mIt; }

    operator value_type&&() && CEXCXX_NOEXCEPT
    { return std::forward(*mIt); }
#pragma clang diagnostic pop
};


template<typename Container, typename Iter>
class insert_iterator
{
private:
    typedef std::iterator_traits<Iter>		traits_type;

protected:

    Container* mContainer;
    Iter mIt;

public:
    typedef Container container_type;
    typedef insert_iterator<container_type, Iter> iterator_type;
    typedef typename traits_type::iterator_category iterator_category;
    typedef typename traits_type::value_type  	value_type;
    typedef typename traits_type::difference_type 	difference_type;
    typedef insert_reference<container_type, Iter> 	reference;
    typedef typename traits_type::pointer   	pointer;

#if __cplusplus > 201703L && __cpp_lib_concepts
    using iterator_concept = std::__detail::__iter_concept<iterator_type>;
#endif


    CEXCXX20_CONSTEXPR
    insert_iterator(Container& c, Iter it) CEXCXX_NOEXCEPT
            : mContainer(&c), mIt(it) {}

    CEXCXX20_CONSTEXPR
    insert_iterator(const insert_iterator& ) CEXCXX_NOEXCEPT = default;

    CEXCXX20_CONSTEXPR
    insert_iterator(insert_iterator&& ) CEXCXX_NOEXCEPT = default;

    CEXCXX20_CONSTEXPR
    insert_iterator& operator=(const insert_iterator& ) CEXCXX_NOEXCEPT = default;

    CEXCXX20_CONSTEXPR
    insert_iterator& operator=(insert_iterator&& ) CEXCXX_NOEXCEPT = default;

    insert_reference<Container, Iter> operator*() CEXCXX_NOEXCEPT
    { return insert_reference<Container, Iter>(*mContainer, mIt); }

    CEXCXX20_CONSTEXPR
    pointer operator->() const CEXCXX_NOEXCEPT
    { return mIt.operator->(); }

    CEXCXX20_CONSTEXPR
    insert_iterator& operator++() CEXCXX_NOEXCEPT
    { ++mIt; return *this; }

    CEXCXX20_CONSTEXPR
    insert_iterator& operator--() CEXCXX_NOEXCEPT
    { --mIt; return *this; }

#pragma clang diagnostic push
#pragma ide diagnostic ignored "cert-dcl21-cpp"
    CEXCXX20_CONSTEXPR
    insert_iterator operator++(int) CEXCXX_NOEXCEPT
    { return insert_iterator(*mContainer, mIt++); }

    CEXCXX20_CONSTEXPR
    insert_iterator operator--(int) CEXCXX_NOEXCEPT
    { return insert_iterator(*mContainer, mIt--); }
#pragma clang diagnostic pop

    CEXCXX20_CONSTEXPR
    reference operator[](difference_type n) const CEXCXX_NOEXCEPT
    { return insert_reference<Container, Iter>(*mContainer, mIt[n]); }

    CEXCXX20_CONSTEXPR
    insert_iterator& operator+=(difference_type n) CEXCXX_NOEXCEPT
    { mIt += n; return *this; }

    CEXCXX20_CONSTEXPR
    insert_iterator operator+(difference_type n) const CEXCXX_NOEXCEPT
    { return insert_iterator(*mContainer, mIt + n); }

    CEXCXX20_CONSTEXPR
    insert_iterator& operator-=(difference_type n) CEXCXX_NOEXCEPT
    { mIt -= n; return *this; }

    CEXCXX20_CONSTEXPR
    insert_iterator operator-(difference_type n) const CEXCXX_NOEXCEPT
    { return insert_iterator(*mContainer, mIt - n); }
};

template<typename Container, typename Iter>
insert_iterator<Container, Iter> smartinserter(Container& c, Iter i) CEXCXX_NOEXCEPT
{ return insert_iterator(c, i); }

}