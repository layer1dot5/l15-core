#pragma once

#include <functional>
#include <future>

#include "common_error.hpp"

namespace l15::service {

class IllegalServiceParameterError : public Error
{
    std::string m_details;
public:
    explicit IllegalServiceParameterError(std::string&& details) noexcept : m_details(move(details)) {}
    IllegalServiceParameterError(IllegalServiceParameterError&& another) noexcept : m_details(move(another.m_details)) {}

    const char* what() const override
    { return "IllegalServiceParameterError"; }

    const char* details() const override
    { return m_details.c_str(); }
};

class GenericService
{
    static std::function<void(Error&&)> m_def_err;
public:
    static void SetDefaultErrorHandler(std::function<void(Error&&)> h)
    { m_def_err = h; }

public:
//    GenericService();
//    ~GenericService();

    std::future<void> Serve(std::function<void()> action,
                            std::function<void()> complete_handler = [](){},
                            std::function<void(Error&&)> error_handler = m_def_err);
};

} // l15::signer_service

