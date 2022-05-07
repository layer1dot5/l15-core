#include <iostream>
#include <filesystem>
#include <cstring>

#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"

#include "util/translation.h"
#include "util/strencodings.h"
#include "script/interpreter.h"

#include "hash_helper.hpp"
#include "script_merkle_tree.hpp"
#include "common.hpp"

using namespace l15;
const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

static const std::string TAPLEAF_TAG = "TapLeaf";
static const bytevector TestData = ParseHex("32b16117e52029c0d76fa42a384e8a55e378a27cc03a73a010416ac4fb7b92b1");

TEST_CASE("TapLeaf hash")
{
    uint256 reference_taghash;
    uint256 reference_hash;
    uint8_t hash_size = 32;

    std::clog << "Calculate reference tapleaf TAG hash" << std::endl;

    CSHA256().Write((uint8_t*)TAPLEAF_TAG.data(), TAPLEAF_TAG.size()).Finalize(reference_taghash.data());

    std::clog << "Calculate reference tapleaf hash" << std::endl;

    CSHA256()
             .Write(reference_taghash.data(), reference_taghash.size())
             .Write(reference_taghash.data(), reference_taghash.size())
             .Write(&hash_size, 1)
             .Write(TestData.data(), TestData.size())
             .Finalize(reference_hash.data());

    std::clog << "Reference TapLeaf hash: " << HexStr(Span<uint8_t>(reference_hash.begin(), reference_hash.end())) << std::endl;

    std::clog << "Calculate bitcoin tapleaf hash" << std::endl;
    uint256 bitcoin_hash = (CHashWriter(HASHER_TAPLEAF) << TestData).GetSHA256();
    std::clog << "Bitcoin TapLeaf hash: " << HexStr(Span<uint8_t>(bitcoin_hash.begin(), bitcoin_hash.end())) << std::endl;


    std::clog << "Calculate l15 tapleaf hash" << std::endl;
    HashWriter writer(TAPLEAF_HASH);
    writer << TestData;
    uint256 result_hash = writer;

    std::clog << "Test TapLeaf hash: " << HexStr(Span<uint8_t>(result_hash.begin(), result_hash.end())) << std::endl;

    CHECK(result_hash == reference_hash);
}