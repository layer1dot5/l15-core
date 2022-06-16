#include <iostream>
#include <filesystem>
#include <cstring>

#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"

#include "util/translation.h"
#include "util/strencodings.h"
#include "script/interpreter.h"
#include "script/standard.h"
#include "pubkey.h"

#include "hash_helper.hpp"
#include "script_merkle_tree.hpp"
#include "channel_keys.hpp"
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

TEST_CASE("TapTweak")
{
    api::WalletApi wallet(api::ChainMode::MODE_REGTEST);

    ChannelKeys key(wallet);

    // Lets just simulate some uint256
    HashWriter hash(TAPBRANCH_HASH);
    hash  << "test test test";
    uint256 fake_root = hash;

    auto taprootkey = key.AddTapTweak(fake_root);


    XOnlyPubKey xonlypubkey(taprootkey.first);

    CHECK(xonlypubkey.CheckTapTweak(XOnlyPubKey(key.GetPubKey()), fake_root, taprootkey.second));

}

TEST_CASE("TapRoot single script")
{
    api::WalletApi wallet(api::ChainMode::MODE_REGTEST);

    //get key pair Taproot
    auto internal_sk = wallet.CreateNewKey();
    const auto& internal_pk = internal_sk.GetLocalPubKey();

    std::clog << "Internal PK: " << HexStr(internal_pk) << std::endl;

    //get key pair script
    auto script_sk = wallet.CreateNewKey();
    const auto& script_pk = script_sk.GetPubKey();
    std::string script_pk_str = HexStr(script_pk);

    std::clog << "Script PK: " << script_pk_str << std::endl;

    CScript script;
    script << ParseHex(script_pk_str);
    script << OP_CHECKSIG;


    ScriptMerkleTree tap_tree (TreeBalanceType::WEIGHTED, {script});
    uint256 root = tap_tree.CalculateRoot();

    auto tap_root = internal_sk.AddTapTweak(std::make_optional(root));


    XOnlyPubKey xonly_internal_pubkey(internal_pk);
    TaprootBuilder builder;
    builder.Add(0, script, TAPROOT_LEAF_TAPSCRIPT);

    CHECK(builder.IsComplete());

    builder.Finalize(xonly_internal_pubkey);

    auto TapRootKeyBtc = builder.GetOutput();

    CHECK(std::equal(TapRootKeyBtc.begin(), TapRootKeyBtc.end(), tap_root.first.begin()));

}

