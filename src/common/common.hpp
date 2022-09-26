#pragma once

#include <string>
#include <vector>
#include <array>
#include <memory>
#include <functional>
#include <iostream>
#include <tuple>

#include "fixsizevector.hpp"

#include "primitives/transaction.h"

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


typedef cex::fixsize_vector<uint8_t, 32> seckey;
typedef cex::fixsize_vector<uint8_t, 33> compressed_pubkey;

class xonly_pubkey : public cex::fixsize_vector<uint8_t, 32>
{
public:
    typedef cex::fixsize_vector<uint8_t, 32> base;
    typedef base::base base_vector;

    xonly_pubkey() = default;
    xonly_pubkey(const xonly_pubkey&) = default;
    xonly_pubkey(xonly_pubkey&&) = default;
    xonly_pubkey(const secp256k1_context *ctx, const secp256k1_xonly_pubkey &pk)
    : cex::fixsize_vector<uint8_t, 32>()
    { set(ctx, pk); }

    xonly_pubkey& operator=(const xonly_pubkey&) = default;
    xonly_pubkey& operator=(xonly_pubkey&&) = default;

    const base_vector& get_vector() const noexcept
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

typedef cex::fixsize_vector<uint8_t, 64> signature;

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
    size_t operator()(const T& val) const
    { return std::_Hash_bytes(val.data(), val.size(), static_cast<size_t>(0xb74a5b734)); }
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
}
