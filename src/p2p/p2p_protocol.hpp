#pragma once

#include <stdexcept>
#include <sstream>
#include <type_traits>

namespace l15::p2p {

enum class PROTOCOL: uint16_t {
    FROST = 1,
    WRONG_PROTOCOL
};


template <typename STREAM>
STREAM& operator << (STREAM& s, const PROTOCOL& p)
{ return s << static_cast<std::underlying_type<PROTOCOL>::type>(p); }

template <typename STREAM>
STREAM& operator >> (STREAM& s, PROTOCOL& p)
{ return s >> reinterpret_cast<std::underlying_type<PROTOCOL>::type&>(p); }

}