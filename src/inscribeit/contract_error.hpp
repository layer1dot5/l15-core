#pragma once

#include "common_error.hpp"

namespace l15::inscribeit {

class ContractError : public Error {
public:
    explicit ContractError(std::string&& details) : Error(move(details)) {}
    ~ContractError() override = default;

    const char* what() const noexcept override
    { return "ContractError"; }
};

class ContractTermMissing : public ContractError {
public:
    explicit ContractTermMissing(std::string&& details) : ContractError(move(details)) {}
    ~ContractTermMissing() override = default;

    const char* what() const noexcept override
    { return "ContractTermsMissing"; }
};

class ContractTermWrongValue : public ContractError {
public:
    explicit ContractTermWrongValue(std::string&& details) : ContractError(move(details)) {}
    ~ContractTermWrongValue() override = default;

    const char* what() const noexcept override
    { return "ContractTermWrongValue"; }
};

class ContractTermValueMismatch : public ContractError {
public:
    explicit ContractTermValueMismatch(std::string&& details) : ContractError(move(details)) {}
    ~ContractTermValueMismatch() override = default;

    const char* what() const noexcept override
    { return "ContractTermValueMismatch"; }
};

class ContractTermWrongFormat : public ContractError {
public:
    explicit ContractTermWrongFormat(std::string&& details) : ContractError(move(details)) {}
    ~ContractTermWrongFormat() override = default;

    const char* what() const noexcept override
    { return "ContractTermWrongFormat"; }
};

class ContractProtocolError : public ContractError {
public:
    explicit ContractProtocolError(std::string&& details) : ContractError(move(details)) {}
    ~ContractProtocolError() override = default;

    const char* what() const noexcept override
    { return "ContractProtocolError"; }
};

}