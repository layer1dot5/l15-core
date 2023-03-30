%module libl15_core_pybind

%include "std_string.i"
%include "std_vector.i"

%template(StringVector) std::vector<std::string>;

%{
const std::string build_time = __DATE__ " " __TIME__;

const std::string Version() {
    return build_time;
}
%}

%inline %{
    const std::string Version();
%}
