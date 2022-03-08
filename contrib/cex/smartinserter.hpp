#pragma once

#include <iterator>

namespace cex {

template<typename Container, typename Iter>
struct insert_reference {
    typedef std::iterator_traits<Iter>		traits_type;
    typedef typename traits_type::value_type value_type;
    typedef typename traits_type::reference reference;

    Container& mContainer;
    Iter& mIt;

    insert_reference(Container& c, Iter& it) noexcept
            : mContainer(c), mIt(it) {}

    insert_reference(const insert_reference& ) noexcept = default;
    insert_reference(insert_reference&&) noexcept = default;

    insert_reference& operator=(const value_type& v)
    { mIt = mContainer.insert(mIt, v); return *this; }

    insert_reference& operator=(value_type&& v)
    { mIt = mContainer.insert(mIt, std::move(v)); return *this; }

#pragma clang diagnostic push
#pragma ide diagnostic ignored "google-explicit-constructor"
    operator value_type()
    { return *mIt; }

    operator reference()
    { return *mIt;}

    operator const reference() const
    { return *mIt; }
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
    typedef typename traits_type::iterator_category iterator_category;
    typedef typename traits_type::value_type  	value_type;
    typedef typename traits_type::difference_type 	difference_type;
    typedef insert_reference<container_type, Iter> 	reference;
    typedef typename traits_type::pointer   	pointer;

    insert_iterator(Container& c, Iter it) noexcept
            : mContainer(&c), mIt(it) {}

    insert_iterator(const insert_iterator& ) noexcept = default;
    insert_iterator(insert_iterator&& ) noexcept = default;

    insert_iterator& operator=(const insert_iterator& ) noexcept = default;
    insert_iterator& operator=(insert_iterator&& ) noexcept = default;

    insert_reference<Container, Iter> operator*() noexcept
    { return insert_reference<Container, Iter>(*mContainer, mIt); }

    pointer operator->() const noexcept
    { return mIt.operator->(); }

    insert_iterator& operator++() noexcept
    { ++mIt; return *this; }

    insert_iterator& operator--() noexcept
    { --mIt; return *this; }

#pragma clang diagnostic push
#pragma ide diagnostic ignored "cert-dcl21-cpp"
    insert_iterator operator++(int) noexcept
    { return insert_iterator(*mContainer, mIt++); }

    insert_iterator operator--(int) noexcept
    { return insert_iterator(*mContainer, mIt--); }
#pragma clang diagnostic pop

    reference operator[](difference_type n) const noexcept
    { return insert_reference<Container, Iter>(*mContainer, mIt[n]); }

    insert_iterator& operator+=(difference_type n) noexcept
    { mIt += n; return *this; }

    insert_iterator operator+(difference_type n) const noexcept
    { return insert_iterator(*mContainer, mIt + n); }

    insert_iterator& operator-=(difference_type n) noexcept
    { mIt -= n; return *this; }

    insert_iterator operator-(difference_type n) const noexcept
    { return insert_iterator(*mContainer, mIt - n); }
};

template<typename Container, typename Iter>
insert_iterator<Container, Iter> smartinserter(Container& c, Iter i) noexcept
{ return insert_iterator(c, i); }

}