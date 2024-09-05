#pragma once

#include <string>

#include "common.hpp"

namespace l15::core {

class MnemonicCheckSumError : public Error
{
public:
    MnemonicCheckSumError() = default;
    explicit MnemonicCheckSumError(std::string&& details) : Error(move(details)) {}
    ~MnemonicCheckSumError() override = default;

    const char* what() const noexcept override
    { return "MnemonicCheckSumError"; }

};

class MnemonicLengthError : public Error
{
public:
    // MnemonicDictionaryError() = default;
    explicit MnemonicLengthError(std::string&& details) : Error(move(details)) {}
    ~MnemonicLengthError() override = default;

    const char* what() const noexcept override
    { return "MnemonicLengthError"; }

};

class MnemonicDictionaryError : public Error
{
public:
    // MnemonicDictionaryError() = default;
    explicit MnemonicDictionaryError(std::string&& details) : Error(move(details)) {}
    ~MnemonicDictionaryError() override = default;

    const char* what() const noexcept override
    { return "MnemonicDictionaryError"; }

};

class MnemonicParser
{
    stringvector dictionary;

public:
    explicit MnemonicParser(stringvector word_list);
    sensitive_bytevector DecodeEntropy(const sensitive_stringvector& phrase) const;
    sensitive_stringvector EncodeEntropy(sensitive_bytevector entropy) const;

    sensitive_bytevector MakeSeed(const sensitive_stringvector& phrase, const sensitive_string& passphrase) const;
};

}