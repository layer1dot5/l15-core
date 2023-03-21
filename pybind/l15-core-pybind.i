%module libl15_core_pybind

%include "std_shared_ptr.i"
%include "std_string.i"
%include "std_vector.i"
%include "std_map.i"

/*
%include "l15-core-pybind.hpp"

%include "../contrib/cex/fixsizevector.hpp"
%include "../src/core/channel_keys.hpp"

%template(StringVector) std::vector<std::string>;

struct secp256k1_context_struct;
%template(FixsizeUintVector32) cex::fixsize_vector<uint8_t, 32>;
class ChannelKeysImpl;
*/

%{
    const std::string build_time = __DATE__ " " __TIME__;

    const std::string Version() {
        return build_time;
    }
%}

%inline %{
    const std::string Version();
%}
