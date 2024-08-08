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

MnemonicParser::MnemonicParser(stringvector word_list)
{
    if (word_list.size() != 2048) throw MnemonicDictionaryError("wrong size: " + std::to_string(word_list.size()));
    dictionary = move(word_list);
}


MnemonicParser::entropy_type MnemonicParser::DecodeEntropy(const stringvector &phrase) const
{
    switch(phrase.size()) {
    case 12: case 15: case 18: case 21: case 24:
        break;
    default:
        throw MnemonicLengthError(std::to_string(phrase.size()));
    }

    std::vector<uint16_t, secure_allocator<uint16_t>> indexes;
    indexes.reserve(phrase.size());
    for(const auto& word: phrase) {
        if (auto pos = std::ranges::lower_bound(dictionary, word); pos != dictionary.end() && *pos == word) {
            indexes.emplace_back(pos - dictionary.begin());
        }
        else throw MnemonicDictionaryError(word + " not found");
    }

    entropy_type entropy;
    entropy.reserve(phrase.size() * 11 / 8 + 1);
    ConvertBits<11, 8, true>([&entropy](uint8_t c){ entropy.push_back(c); }, indexes.begin(), indexes.end());

    uint8_t checksum = entropy.back();
    entropy.pop_back();

    uint8_t checksum_mask = std::numeric_limits<uint8_t>::max() << (8 - entropy.size() / 4);

    bytevector h = cryptohash<bytevector>(entropy, CSHA256());

    if (checksum != (h.front() & checksum_mask)) throw MnemonicCheckSumError();

    return entropy;
}

stringvector MnemonicParser::EncodeEntropy(entropy_type entropy) const
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

    stringvector phrase;
    std::ranges::transform(indexes, cex::smartinserter(phrase, phrase.end()), [&](auto i)->string{return dictionary[i]; });

    return phrase;
}


template <typename C>
constexpr C convert_endian(C vals, const std::endian e) noexcept
{
    if (std::endian::native != e) std::for_each(vals.begin(), vals.end(), [](auto& v){ v = std::byteswap(v); });
    return vals;
}

MnemonicParser::entropy_type MnemonicParser::MakeSeed(const stringvector& phrase, const std::string& passphrase) const
{
    static const char* prefix = "mnemonic";

    // Decode to veryfy checksum
    DecodeEntropy(phrase);

    std::ostringstream buf;
    bool insert_space = false;
    for (const auto& w: phrase) {
        if (insert_space)
            buf << ' ';
        else
            insert_space = true;
        buf << w;
    }

    std::string wholephrase = buf.str();
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

    entropy_type res;
    res.reserve(CHMAC_SHA512::OUTPUT_SIZE);
    std::ranges::transform(hash_t, cex::smartinserter(res, res.end()), [](auto v){ return v; });

    return res;
}

}
