#include "mnemonic.hpp"
#include "utils.hpp"
#include "hash_helper.hpp"

#include <algorithm>
#include <ranges>
#include <utility>
#include <bit>

#include "hmac_sha512.h"

namespace l15::core {


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
