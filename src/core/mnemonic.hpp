#pragma once

#include <string>
#include <type_traits>

#include "smartinserter.hpp"

#include "common.hpp"
#include "utils.hpp"

#include "util/strencodings.h"
#include "sha256.h"

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
public:
    virtual ~MnemonicParserBase() = default;

    virtual sensitive_bytevector DecodeEntropy(const sensitive_stringvector& phrase) const = 0;
    virtual sensitive_stringvector EncodeEntropy(sensitive_bytevector entropy) const = 0;

    sensitive_bytevector MakeSeed(const sensitive_stringvector& phrase, const sensitive_string& passphrase) const;
};

template <typename D>
class MnemonicParser : public MnemonicParserBase
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
    MnemonicParser(const MnemonicParser&) noexcept = delete;
    MnemonicParser(MnemonicParser&&) noexcept = default;
    ~MnemonicParser() override = default;

    MnemonicParser& operator=(const MnemonicParser&) = delete;
    MnemonicParser& operator=(MnemonicParser&&) = default;

    sensitive_bytevector DecodeEntropy(const sensitive_stringvector &phrase) const override
    {
        switch(phrase.size()) {
        case 12: case 15: case 18: case 21: case 24:
            break;
        default:
            throw MnemonicLengthError(std::to_string(phrase.size()));
        }

        std::vector<uint16_t, secure_allocator<uint16_t>> indexes;
        indexes.reserve(phrase.size());
        for(const auto& sens_word: phrase) {
            std::string word(sens_word);
            if (auto pos = std::lower_bound(GetDictionary().begin(), GetDictionary().end(), word); pos != GetDictionary().end() && *pos == word) {
                indexes.emplace_back(pos - GetDictionary().begin());
            }
            else throw MnemonicDictionaryError(word + " not found");
        }

        sensitive_bytevector entropy;
        entropy.reserve(phrase.size() * 11 / 8 + 1);
        ConvertBits<11, 8, true>([&entropy](uint8_t c){ entropy.push_back(c); }, indexes.begin(), indexes.end());

        uint8_t checksum = entropy.back();
        entropy.pop_back();

        uint8_t checksum_mask = std::numeric_limits<uint8_t>::max() << (8 - entropy.size() / 4);

        auto h = cryptohash<bytevector>(entropy, CSHA256());

        if (checksum != (h.front() & checksum_mask)) throw MnemonicCheckSumError();

        return entropy;
    }

    sensitive_stringvector EncodeEntropy(sensitive_bytevector entropy) const override
    {
        switch (entropy.size()) {
        case 16: case 20: case 24: case 28: case 32:
            break;
        default:
            throw MnemonicLengthError(std::to_string(entropy.size()));
        }

        uint8_t checksum_mask = std::numeric_limits<uint8_t>::max() << (8 - entropy.size() / 4);
        bytevector h = cryptohash<bytevector>(entropy, CSHA256());
        entropy.push_back(h.front() & checksum_mask);

        std::vector<uint16_t, secure_allocator<uint16_t>> indexes;
        indexes.reserve(entropy.size() * 8 / 11 + 1);

        ConvertBits<8, 11, false>([&indexes](size_t i){ indexes.push_back(i); }, entropy.begin(), entropy.end());

        sensitive_stringvector phrase;
        phrase.reserve(indexes.size());
        std::ranges::transform(indexes, cex::smartinserter(phrase, phrase.end()), [&](auto i){return sensitive_string(GetDictionary()[i]); });

        return phrase;
    }

};

template <typename D>
MnemonicParser<D> make_mnemonic_parser(D&& dictionary)
{ return MnemonicParser<D>(std::forward<D>(dictionary)); }


}