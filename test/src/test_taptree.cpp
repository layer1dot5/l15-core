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
static const uint8_t TAPLEAF_VERSION = 0xc0;
static const CScript TestScript = CScript() << ParseHex("db1ff3f207771e90ec30747525abaefd3b56ff2b3aecbb76809b7106617c442e") << OP_CHECKSIG;

// Reference hash is now calculated with the excessive byte fed to the hash
// This way test now complies to bitcoin implementation but BIP340 reference implementation
TEST_CASE("TapLeaf hash")
{
    uint256 reference_taghash;
    uint256 reference_hash;
    uint8_t script_size = TestScript.size();

    std::clog << "Calculate reference tapleaf TAG hash" << std::endl;

    CSHA256().Write((uint8_t*)TAPLEAF_TAG.data(), TAPLEAF_TAG.size()).Finalize(reference_taghash.data());

    std::clog << "Calculate reference tapleaf hash" << std::endl;

    CSHA256()
             .Write(reference_taghash.data(), reference_taghash.size())
             .Write(reference_taghash.data(), reference_taghash.size())
             .Write(&TAPLEAF_VERSION, 1)
             .Write(&script_size, 1) // ! This byte is excessive compared to BIP
             .Write(TestScript.data(), TestScript.size())
             .Finalize(reference_hash.data());

    std::clog << "Reference TapLeaf hash: " << HexStr(Span<uint8_t>(reference_hash.begin(), reference_hash.end())) << std::endl;

    std::clog << "Calculate bitcoin tapleaf hash" << std::endl;
    uint256 bitcoin_hash = (CHashWriter(HASHER_TAPLEAF) << TAPLEAF_VERSION << TestScript).GetSHA256();
    std::clog << "Bitcoin TapLeaf hash: " << HexStr(Span<uint8_t>(bitcoin_hash.begin(), bitcoin_hash.end())) << std::endl;


    std::clog << "Calculate l15 tapleaf hash" << std::endl;
    HashWriter writer(TAPLEAF_HASH);
    writer << TAPLEAF_VERSION << TestScript;
    uint256 result_hash = writer;

    std::clog << "Test TapLeaf hash: " << HexStr(Span<uint8_t>(result_hash.begin(), result_hash.end())) << std::endl;

    CHECK(bitcoin_hash == reference_hash);
    CHECK(result_hash == reference_hash);
}