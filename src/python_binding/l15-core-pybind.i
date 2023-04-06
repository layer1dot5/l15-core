%module libl15_core_pybind

%include "std_shared_ptr.i"
%include "std_string.i"
%include "std_vector.i"
%include "std_map.i"
%include "exception.i"

%apply unsigned int { uint32_t }
%apply unsigned long long { uint64_t }

%include "../../src/common/common_error.hpp"

%template(StringVector) std::vector<std::string>;
%template(SharedL15Error) std::shared_ptr<l15::Error>;
%template(SharedError) std::shared_ptr<python_binding::Exception>;

%{

#include <typeinfo>
#include <iostream>

#include <cxxabi.h>

#include "create_inscription.hpp"
#include "contract_builder.hpp"
#include "common_error.hpp"
#include "python_exception.hpp"

const std::string build_time = __DATE__ " " __TIME__;

const std::string Version() {
    return build_time;
}
%}

%exception {
    try {
        $action
        } catch (std::exception& e) {
            auto exceptionCopy = std::make_exception_ptr(e);
            const std::type_info &t = typeid(e);
            PyErr_SetString(PyExc_Exception, e.what());
            SWIG_fail;
        }
}

%include "create_inscription.hpp"

%inline %{
    const std::string Version();
%}
