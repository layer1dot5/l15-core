#pragma once

#include <stdexcept>

namespace l15 {

class Error : std::exception {
public:
    ~Error() override = default;

    const char* what() const noexcept override  = 0;
    virtual const char* details() const noexcept {return ""; }
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
    const std::string m_details;
public:
    explicit SignatureError(std::string&& details) : m_details(move(details)) {}
    ~SignatureError() override = default;

    const char* what() const noexcept override
    { return "SignatureError"; }

};

}