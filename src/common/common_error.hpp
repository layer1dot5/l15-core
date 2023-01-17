#pragma once

#include <stdexcept>

namespace l15 {

class Error : std::exception {
    const std::string m_details;
public:
    Error() noexcept = default;
    Error(const Error&) = default;
    Error(Error&&) noexcept = default;
    explicit Error(std::string&& details) noexcept : m_details(move(details)) {}
    ~Error() override = default;

    const char* what() const noexcept override  = 0;
    virtual const char* details() const noexcept { return m_details.c_str(); }
};

class KeyError : public Error {
public:
    ~KeyError() override = default;

    const char* what() const noexcept override
    { return "KeyError"; }
};

class WrongKeyError : public KeyError {
public:
    ~WrongKeyError() override = default;

    const char* what() const noexcept override
    { return "WrongKeyError"; }
};

class SignatureError : public Error {
public:
    explicit SignatureError(std::string&& details) : Error(move(details)) {}
    ~SignatureError() override = default;

    const char* what() const noexcept override
    { return "SignatureError"; }

};

}