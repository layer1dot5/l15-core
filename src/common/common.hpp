#pragma once

#include <string>
#include <vector>
#include <array>
#include <memory>
#include <functional>
#include <iostream>
#include <tuple>
#include <charconv>

#include "fixsizevector.hpp"

#include "primitives/transaction.h"
#include "allocators/secure.h"

#include "secp256k1_extrakeys.h"

#include "common_error.hpp"

using std::string;
using std::cout;
using std::cerr;
using std::clog;
using std::stringstream;

namespace l15 {

using std::get;
using std::move;

typedef std::vector<uint8_t> bytevector;
typedef std::vector<std::string> stringvector;


typedef cex::fixsize_vector<uint8_t, 32, secure_allocator<unsigned char>> seckey;
typedef cex::fixsize_vector<uint8_t, 33> compressed_pubkey;

class xonly_pubkey : public cex::fixsize_vector<uint8_t, 32>
{
public:
    typedef cex::fixsize_vector<uint8_t, 32> base;
    typedef base::base base_vector;

    xonly_pubkey() = default;
    xonly_pubkey(const xonly_pubkey&) = default;
    xonly_pubkey(xonly_pubkey&&) noexcept = default;
    xonly_pubkey(const base::base& v) : cex::fixsize_vector<uint8_t, 32>(v) {}
    xonly_pubkey(base::base&& v) noexcept : cex::fixsize_vector<uint8_t, 32>(move(v)) {}
    xonly_pubkey(const secp256k1_context *ctx, const secp256k1_xonly_pubkey &pk)
    : cex::fixsize_vector<uint8_t, 32>()
    { set(ctx, pk); }

    xonly_pubkey& operator=(const xonly_pubkey&) = default;
    xonly_pubkey& operator=(xonly_pubkey&&) = default;

    const base_vector& get_vector() const noexcept
    { return *this; }

    base_vector& get_vector() noexcept
    { return *this; }

    void set(const secp256k1_context *ctx, const secp256k1_xonly_pubkey &pk)
    {
        if (!secp256k1_xonly_pubkey_serialize(ctx, data(), &pk)) {
            throw KeyError();
        }
    }

    secp256k1_xonly_pubkey get(const secp256k1_context *ctx) const {
        secp256k1_xonly_pubkey pk;
        if (!secp256k1_xonly_pubkey_parse(ctx, &pk, data())) {
            throw KeyError();
        }
        return pk;
    }
    void get(const secp256k1_context *ctx, secp256k1_xonly_pubkey& pk) const {
        if (!secp256k1_xonly_pubkey_parse(ctx, &pk, data())) {
            throw KeyError();
        }
    }

};

CScript& operator<<(CScript& script, const xonly_pubkey& pk);

template <class STREAM>
STREAM& operator << (STREAM& s, const xonly_pubkey& x)
{ return operator<<(s, reinterpret_cast<const xonly_pubkey::base&>(x)); }

template <class STREAM>
STREAM& operator >> (STREAM& s, xonly_pubkey& x)
{ return operator>>(s, reinterpret_cast<xonly_pubkey::base&>(x)); }

class signature: public bytevector {
public:
    signature() : bytevector(65) { resize(64); }
};

typedef std::unique_ptr<CMutableTransaction> transaction_ptr;
typedef std::tuple<CMutableTransaction, bytevector> transaction_psig_t;


template<typename T>
static bool IsZeroArray(const T& a)
{ bool res = false; std::for_each(a.begin(), a.end(), [&](const uint8_t& el){ res |= el; }); return !res;}

template<typename T>
static bool IsZeroArray(const T* a, size_t len)
{ bool res = false; std::for_each(a, a+len, [&](const uint8_t& el){ res |= el; }); return !res;}

template <class T>
struct hash : public std::__hash_base<size_t, T>
{
    typedef T value_type;
    size_t operator()(const value_type& val) const
    { return std::_Hash_bytes(val.data(), val.size(), static_cast<size_t>(0xb74a5b734)); }
};

template <class T>
struct hash<T*> : public std::__hash_base<size_t, T*>
{
    //typedef std::remove_cv<T*> value_type;
    size_t operator()(const T* val) const
    { return std::_Hash_bytes(val->data(), val->size(), static_cast<size_t>(0xb74a5b734)); }
};

template <typename T>
struct equal_to : public std::equal_to<T> {};

template <typename T>
struct equal_to<T*>
{
    constexpr bool operator()(const T* x, const T* y) const
    { return *x == *y; }
};

template <typename T>
struct less : std::less<T> {};

template <>
struct less<xonly_pubkey>
{
    bool operator()(const xonly_pubkey& x, const xonly_pubkey& y) const
    { return x.get_vector() < y.get_vector(); }
};


template<>
struct hash<secp256k1_xonly_pubkey> : std::__hash_base<size_t, secp256k1_xonly_pubkey>
{
    size_t operator()(const secp256k1_xonly_pubkey& val) const
    { return std::_Hash_bytes(val.data, sizeof(val.data), static_cast<size_t>(0xb74a5b734)); }
};

struct secp256k1_xonly_pubkey_equal
{
    bool operator() (const secp256k1_xonly_pubkey& p1, const secp256k1_xonly_pubkey& p2) const
    { return memcmp(p1.data, p2.data, sizeof(p1.data)) == 0; }
};

extern const std::array<std::array<char, 2>, 256> byte_to_hex;

template<unsigned N>
std::string hex(const unsigned char (&s)[N])
{
    std::string res(N * 2, '\0');

    char* it = res.data();
    for (uint8_t v : s) {
        *it = byte_to_hex[v][0];
        ++it;
        *it = byte_to_hex[v][1];
        ++it;
    }

    assert(it == res.data() + res.size());
    return res;
}

template<typename SPAN>
std::string hex(const SPAN& s)
{
    std::string res(s.size() * 2, '\0');

    char* it = res.data();
    for (uint8_t v : s) {
        *it = byte_to_hex[v][0];
        ++it;
        *it = byte_to_hex[v][1];
        ++it;
    }

    assert(it == res.data() + res.size());
    return res;
}

template<typename R>
R unhex(std::string_view str) {
    if (str.length()%2) {
        throw std::out_of_range("Wrong hex string length");
    }

    R res;
    res.resize(str.length() / 2);

    auto ins = res.begin();
    for (auto i = str.begin(); i != str.end(); i+=2) {
        auto conv_res = std::from_chars(i, i+2, *ins++, 16);
        if (conv_res.ec == std::errc::invalid_argument) {
            throw std::invalid_argument("Wrong hex string");
        }
    }
    return res;
}

}
