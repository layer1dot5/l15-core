#pragma once

#include <string>
#include <vector>
#include <array>
#include <memory>
#include <iostream>

#include "fixsizevector.hpp"

#include "primitives/transaction.h"

#include "secp256k1_extrakeys.h"

#include "core_error.hpp"

using std::string;
using std::cout;
using std::cerr;
using std::clog;
using std::stringstream;

namespace l15 {

typedef std::vector<uint8_t> bytevector;
typedef std::vector<std::string> stringvector;

namespace core {

typedef cex::fixsize_vector<uint8_t, 32> seckey;
typedef cex::fixsize_vector<uint8_t, 33> compressed_pubkey;

class xonly_pubkey : public cex::fixsize_vector<uint8_t, 32>
{
public:
    xonly_pubkey() = default;
    xonly_pubkey(const xonly_pubkey&) = default;
    xonly_pubkey(xonly_pubkey&&) = default;
    xonly_pubkey(const secp256k1_context *ctx, const secp256k1_xonly_pubkey &pk)
    : cex::fixsize_vector<uint8_t, 32>()
    { set(ctx, pk); }

    xonly_pubkey& operator=(const xonly_pubkey&) = default;
    xonly_pubkey& operator=(xonly_pubkey&&) = default;

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

typedef cex::fixsize_vector<uint8_t, 64> signature;

typedef std::unique_ptr<CMutableTransaction> transaction_ptr;
typedef std::tuple<CMutableTransaction, bytevector> transaction_psig_t;

}

enum class ChainMode {/*MODE_UNKNOWN, */MODE_MAINNET, MODE_TESTNET, MODE_REGTEST};
}
