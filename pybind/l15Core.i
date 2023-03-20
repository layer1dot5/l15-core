%module l15Core

%include "std_shared_ptr.i"
%include "std_string.i"
%include "std_vector.i"
%include "std_map.i"

%template(StringVector) std::vector<std::string>;

%{
    #include "l15-core-pybind.cpp"

    const std::string build_time = __DATE__ " " __TIME__;
%}
