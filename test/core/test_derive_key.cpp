#include <iostream>
#include <filesystem>
#include <cstring>

#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"

#include "util/translation.h"
#include "master_key.hpp"
#include "utils.hpp"

using namespace l15;
using namespace l15::core;

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

static const std::vector<std::byte> seed = unhex<std::vector<std::byte>>(
        "b37f263befa23efb352f0ba45a5e452363963fabc64c946a75df155244630ebaa1ac8056b873e79232486d5dd36809f8925c9c5ac8322f5380940badc64cc6fe");

static const auto bech = Bech32Coder<IBech32Coder::BTC, IBech32Coder::TESTNET>();

static const std::vector<uint32_t> derive_branches = {
        MasterKey::BIP86_TAPROOT_ACCOUNT | MasterKey::BIP32_HARDENED_KEY_LIMIT,
        2 | MasterKey::BIP32_HARDENED_KEY_LIMIT,
        MasterKey::BIP32_HARDENED_KEY_LIMIT,
        0, 0};

static const std::string derive_path = "m/86'/2'/0'/0/0";

TEST_CASE("Seed")
{
    MasterKey extkey(seed);
    REQUIRE(bech.Encode(extkey.MakeKey(false).GetLocalPubKey()) == "tb1pz6zkdhjmar4x243yve469lex9htp8j2qzcu79s7mm420hddmwxssmngtnz");
}

TEST_CASE("Derive")
{
    MasterKey master(seed);

    ChannelKeys derived = master.Derive(derive_branches, AUTO);

    REQUIRE(bech.Encode(derived.GetLocalPubKey()) == "tb1ptnn4tufj4yr8ql0e8w8tye7juxzsndnxgnlehfk2p0skftzks20sncm2dz");
}

TEST_CASE("DerivePath")
{
    MasterKey master(seed);

    ChannelKeys derived = master.Derive(derive_path, false);

    REQUIRE(bech.Encode(derived.GetLocalPubKey()) == "tb1ptnn4tufj4yr8ql0e8w8tye7juxzsndnxgnlehfk2p0skftzks20sncm2dz");
}
