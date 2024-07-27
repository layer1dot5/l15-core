#pragma once

#include <string>

#include "nlohmann/json.hpp"

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
    typedef std::vector<uint8_t, secure_allocator<uint8_t>> entropy_type;

    explicit MnemonicParser(std::string word_list_json);
    entropy_type DecodeEntropy(const stringvector& phrase) const;
    stringvector EncodeEntropy(entropy_type entropy) const;

    entropy_type MakeSeed(const stringvector& phrase, const std::string& passphrase) const;
};

}