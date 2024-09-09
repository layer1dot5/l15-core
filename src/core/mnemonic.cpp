#include "mnemonic.hpp"
#include "utils.hpp"
#include "hash_helper.hpp"

#include <algorithm>
#include <ranges>
#include <utility>
#include <bit>

#include "util/strencodings.h"
#include "hmac_sha512.h"

namespace l15::core {

sensitive_bytevector MnemonicParserBase::DecodeEntropy(const sensitive_stringvector &phrase) const
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
        if (auto pos = std::ranges::lower_bound(GetDictionary(), word); pos != GetDictionary().end() && *pos == word) {
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

sensitive_stringvector MnemonicParserBase::EncodeEntropy(sensitive_bytevector entropy) const
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


template <typename C>
constexpr C convert_endian(C vals, const std::endian e) noexcept
{
    if (std::endian::native != e) std::for_each(vals.begin(), vals.end(), [](auto& v){ v = std::byteswap(v); });
    return vals;
}

sensitive_bytevector MnemonicParserBase::MakeSeed(const sensitive_stringvector& phrase, const sensitive_string& passphrase) const
{
    static const char* prefix = "mnemonic";

    // Decode to veryfy checksum
    DecodeEntropy(phrase);

    size_t phrase_len = phrase.size() - 1;
    for (const auto& word: phrase) phrase_len += word.length();
    sensitive_string wholephrase;
    wholephrase.reserve(phrase_len);
    for (bool insert_space = false; const auto& w: phrase) {
        if (insert_space)
            wholephrase += ' ';
        else
            insert_space = true;
        wholephrase += w;
    }

    CHMAC_SHA512 cached_hasher((uint8_t*)wholephrase.data(), wholephrase.length());

    std::array<uint8_t, CHMAC_SHA512::OUTPUT_SIZE> hash_u;
    std::array<uint8_t, 4> block_index = {0, 0, 0, 1};

    auto hasher_1 = cached_hasher;
    hasher_1.Write((const uint8_t*)prefix, strlen(prefix));

    if (passphrase.length() > 0)
        hasher_1.Write((const uint8_t*)passphrase.data(), passphrase.length());

    hasher_1.Write(block_index.data(), block_index.size());
    hasher_1.Finalize(hash_u.data());

    std::array<uint8_t, CHMAC_SHA512::OUTPUT_SIZE> hash_t = hash_u;

    for (size_t c = 1; c < 2048; ++c) {
        CHMAC_SHA512 hasher_u = cached_hasher;
        hasher_u.Write(hash_u.data(), hash_u.size());
        hasher_u.Finalize(hash_u.data());

        for (auto val: std::ranges::zip_view(hash_t, hash_u)) {
            val.first ^= val.second;
        }
    }

    sensitive_bytevector res;
    res.reserve(CHMAC_SHA512::OUTPUT_SIZE);
    std::ranges::transform(hash_t, cex::smartinserter(res, res.end()), [](auto v){ return v; });

    return res;
}

}
