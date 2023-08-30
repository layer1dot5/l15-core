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

static const bytevector seed = unhex<bytevector>(
        "b37f263befa23efb352f0ba45a5e452363963fabc64c946a75df155244630ebaa1ac8056b873e79232486d5dd36809f8925c9c5ac8322f5380940badc64cc6fe");

static const auto bech = Bech32Coder<IBech32Coder::BTC, IBech32Coder::TESTNET>();

static const std::vector<uint32_t> derive_branches = {
        MasterKey::BIP86_TAPROOT_ACCOUNT | MasterKey::BIP32_HARDENED_KEY_LIMIT,
        2 | MasterKey::BIP32_HARDENED_KEY_LIMIT,
        MasterKey::BIP32_HARDENED_KEY_LIMIT,
        0, 0};

static const std::string derive_path = "m/86'/2'/0'/0/0";

ChannelKeys mockkey;

TEST_CASE("Seed")
{
    MasterKey extkey(mockkey.Secp256k1Context(), seed);
    REQUIRE(bech.Encode(extkey.MakeKey(false).GetLocalPubKey()) == "tb1pz6zkdhjmar4x243yve469lex9htp8j2qzcu79s7mm420hddmwxssmngtnz");
}

TEST_CASE("Derive")
{
    MasterKey master(mockkey.Secp256k1Context(), seed);

    ChannelKeys derived = master.Derive(derive_branches, AUTO);

    REQUIRE(bech.Encode(derived.GetLocalPubKey()) == "tb1ptnn4tufj4yr8ql0e8w8tye7juxzsndnxgnlehfk2p0skftzks20sncm2dz");
}

TEST_CASE("DerivePath")
{
    MasterKey master(mockkey.Secp256k1Context(), seed);

    ChannelKeys derived = master.Derive(derive_path, false);

    REQUIRE(bech.Encode(derived.GetLocalPubKey()) == "tb1ptnn4tufj4yr8ql0e8w8tye7juxzsndnxgnlehfk2p0skftzks20sncm2dz");
}

TEST_CASE("DerivePubKey")
{
    const uint32_t magic_branch = 34565;

    MasterKey master(mockkey.Secp256k1Context(), seed);

    ext_pubkey extpubkey;
    REQUIRE_NOTHROW(extpubkey = master.MakeExtPubKey());

    REQUIRE_NOTHROW(master.DeriveSelf(magic_branch));
    xonly_pubkey derived_pk;
    REQUIRE_NOTHROW(derived_pk = MasterKey::DerivePubKey(mockkey.Secp256k1Context(), extpubkey, magic_branch));

    ChannelKeys derived_keypair = master.MakeKey(false);

    REQUIRE(hex(derived_pk) == hex(derived_keypair.GetLocalPubKey()));
}

TEST_CASE("DeriveExtPubKey")
{
    const uint32_t magic_branch = 34565;

    MasterKey master(mockkey.Secp256k1Context(), seed);

    ext_pubkey extpubkey;
    REQUIRE_NOTHROW(extpubkey = master.MakeExtPubKey());

    REQUIRE_NOTHROW(master.DeriveSelf(magic_branch));
    ext_pubkey derived_extpk;
    REQUIRE_NOTHROW(derived_extpk = MasterKey::Derive(mockkey.Secp256k1Context(), extpubkey, magic_branch));

    xonly_pubkey derived_pk = MasterKey::GetPubKey(mockkey.Secp256k1Context(), derived_extpk);
    ChannelKeys derived_keypair = master.MakeKey(false);

    REQUIRE(hex(derived_pk) == hex(derived_keypair.GetLocalPubKey()));
}
