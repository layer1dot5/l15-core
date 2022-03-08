#pragma once

#include <string>
#include <vector>
#include <memory>
#include <iostream>

#include "primitives/transaction.h"

using std::string;
using std::cout;
using std::cerr;
using std::clog;
using std::stringstream;
using std::vector;

namespace l15 {

typedef vector<uint8_t> bytevector;
typedef vector<string> stringvector;

typedef std::unique_ptr<CMutableTransaction> transaction_ptr;
typedef std::tuple<CMutableTransaction, bytevector> transaction_psig_t;


}
