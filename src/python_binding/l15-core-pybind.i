%module libl15_core_pybind

%include "std_shared_ptr.i"
%include "std_string.i"
%include "std_vector.i"
%include "std_map.i"

%template(StringVector) std::vector<std::string>;

%{
#include "../../src/inscribeit/create_inscription.hpp"

const std::string build_time = __DATE__ " " __TIME__;

const std::string Version() {
    return build_time;
}
%}

%include "../../src/inscribeit/create_inscription.hpp"

%inline %{
    const std::string Version();
%}
