%module libl15_core_pybind

%include "std_shared_ptr.i"
%include "std_string.i"
%include "std_vector.i"
%include "std_map.i"

%include "../../node/src/support/cleanse.h"

/*


%include "../contrib/cex/fixsizevector.hpp"
%include "../src/core/channel_keys.hpp"

%template(StringVector) std::vector<std::string>;

struct secp256k1_context_struct;
%template(FixsizeUintVector32) cex::fixsize_vector<uint8_t, 32>;
class ChannelKeysImpl;
*/


%{
const std::function<std::string(const char *)> G_TRANSLATION_FUN = nullptr;

#include "../../node/src/support/cleanse.h"

#include "../../src/inscribeit/create_inscription.hpp"

#include "../../node/src/support/lockedpool.h"

const std::string build_time = __DATE__ " " __TIME__;

const std::string Version() {
    return build_time;
}
%}

%include "../../src/inscribeit/create_inscription.hpp"
%include "l15-core-pybind.hpp"

%inline %{
    const std::string Version();
%}
