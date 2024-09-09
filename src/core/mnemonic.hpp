#pragma once

#include <string>
#include <type_traits>

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

class MnemonicParserBase
{
protected:
    virtual const stringvector& GetDictionary() const = 0;
public:
    virtual ~MnemonicParserBase() = default;

    sensitive_bytevector DecodeEntropy(const sensitive_stringvector& phrase) const;
    sensitive_stringvector EncodeEntropy(sensitive_bytevector entropy) const;

    sensitive_bytevector MakeSeed(const sensitive_stringvector& phrase, const sensitive_string& passphrase) const;
};

template <typename D>
class MnemonicParser final : public MnemonicParserBase
{
    D m_word_list;
protected:
    const std::remove_reference_t<D>& GetDictionary() const
    { return m_word_list; }
public:
    explicit MnemonicParser(D&& word_list) : m_word_list(std::forward<D>(word_list))
    {
        if (m_word_list.size() != 2048) throw MnemonicDictionaryError("wrong size: " + std::to_string(m_word_list.size()));
    }
    ~MnemonicParser() override = default;
};

}