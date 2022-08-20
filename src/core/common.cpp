#include "common.hpp"

#include "script/script.h"

namespace l15 {

CScript &operator<<(CScript &script, const xonly_pubkey &pk)
{ return script << pk.get_vector(); }

}
