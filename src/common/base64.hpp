#pragma once

#include "util/strencodings.h"

#include "common_error.hpp"

#include <string>

namespace l15::base64 {

constexpr auto pbase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr int8_t decode64_table[256]{
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1,
    -1, -1, -1, -1, -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
    29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
    49, 50, 51, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

constexpr std::string encode(const auto& input)
{
    std::string str;
    str.reserve(((input.size() + 2) / 3) * 4);
    ConvertBits<8, 6, true>(
        [&](int v) { str += pbase64[v]; },
        input.begin(), input.end(),
        [](const auto& i){ return static_cast<int>(i); });
    while (str.size() % 4) str += '=';
    return str;
}

template <typename R>
constexpr R decode(std::string_view str)
{
    if (str.size() % 4 != 0) throw IllegalArgument("Base64 string length");
    /* One or two = characters at the end are permitted. */

    if (str.size() >= 1 && str.back() == '=') str.remove_suffix(1);
    if (str.size() >= 1 && str.back() == '=') str.remove_suffix(1);

    R ret;
    ret.reserve((str.size() * 3) / 4);
    bool valid = ConvertBits<6, 8, false>(
        [&](uint8_t c) { ret.push_back(static_cast<typename R::value_type>(c)); },
        str.begin(), str.end(),
        [](char c) { return decode64_table[static_cast<uint8_t>(c)]; }
    );
    if (!valid) throw IllegalArgument("Base64 decode");

    return ret;
}

}
