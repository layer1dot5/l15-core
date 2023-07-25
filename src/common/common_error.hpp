#pragma once

#include <stdexcept>

namespace l15 {

class Error : public std::exception {
    const std::string m_details;
public:
    Error() noexcept = default;
    explicit Error(std::string&& details) noexcept : m_details(move(details)) {}
    explicit Error(const char* const details) noexcept : m_details(details) {}
    ~Error() override = default;

    const char* what() const noexcept override = 0;
    virtual const char* details() const noexcept { return m_details.c_str(); }
};

class KeyError : public Error {
public:
    KeyError() = default;
    explicit KeyError(std::string&& details) : Error(move(details)) {}
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

class TransactionError : public Error {
public:
    explicit TransactionError(std::string&& details) : Error(move(details)) {}
    ~TransactionError() override = default;

    const char* what() const noexcept override
    { return "TransactionError"; }

};

class IllegalArgumentError : public Error {
public:
    explicit IllegalArgumentError(std::string&& details) : Error(move(details)) {}
    ~IllegalArgumentError() override = default;

    const char* what() const noexcept override
    { return "IllegalArgumentError"; }

};

}