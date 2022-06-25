#pragma once

#include <string>
#include <vector>
#include <array>
#include <memory>
#include <iostream>

#include "primitives/transaction.h"

using std::string;
using std::cout;
using std::cerr;
using std::clog;
using std::stringstream;

namespace l15 {

typedef std::vector<uint8_t> bytevector;
typedef std::vector<std::string> stringvector;

typedef std::array<uint8_t, 32> seckey;
typedef std::array<uint8_t, 33> compressed_pubkey;
typedef std::array<uint8_t, 32> xonly_pubkey;

typedef std::unique_ptr<CMutableTransaction> transaction_ptr;
typedef std::tuple<CMutableTransaction, bytevector> transaction_psig_t;


}
