#pragma once

#include <exception>

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
    KeyError() noexcept = default;
    explicit KeyError(std::string&& details) noexcept : Error(move(details)) {}
    ~KeyError() override = default;

    const char* what() const noexcept override
    { return "KeyError"; }
};

class WrongKey : public KeyError {
public:
    WrongKey() noexcept = default;
    explicit WrongKey(std::string&& details) noexcept : KeyError(move(details)) {}
    ~WrongKey() override = default;

    const char* what() const noexcept override
    { return "WrongKeyError"; }
};

class SignatureError : public Error {
public:
    SignatureError() noexcept = default;
    explicit SignatureError(std::string&& details) noexcept : Error(move(details)) {}
    ~SignatureError() override = default;

    const char* what() const noexcept override
    { return "SignatureError"; }

};

class TransactionError : public Error {
public:
    explicit TransactionError(std::string&& details) noexcept : Error(move(details)) {}
    ~TransactionError() override = default;

    const char* what() const noexcept override
    { return "TransactionError"; }

};

class IllegalArgument : public Error {
public:
    explicit IllegalArgument(std::string&& details) noexcept : Error(move(details)) {}
    ~IllegalArgument() override = default;

    const char* what() const noexcept override
    { return "IllegalArgumentError"; }

};

class FormatError : public Error {
public:
    explicit FormatError(std::string&& details) noexcept : Error(move(details)) {}
    ~FormatError() override = default;

    const char* what() const noexcept override
    { return "FormatError"; }

};

}