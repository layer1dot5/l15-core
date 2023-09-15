#include <array>

#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"

#include "key_factory.hpp"

using namespace l15;
using namespace l15::core;

static const bytevector seed = unhex<bytevector>(
        "b37f263befa23efb352f0ba45a5e452363963fabc64c946a75df155244630ebaa1ac8056b873e79232486d5dd36809f8925c9c5ac8322f5380940badc64cc6fe");

static const std::vector<uint32_t> derive_branches = {
        MasterKey::BIP86_TAPROOT_ACCOUNT | MasterKey::BIP32_HARDENED_KEY_LIMIT,
        2 | MasterKey::BIP32_HARDENED_KEY_LIMIT,
        MasterKey::BIP32_HARDENED_KEY_LIMIT,
        0 };

static const MasterKey master(seed);

const std::array<uint32_t, 1> branches = {6748};

TEST_CASE("KeyFactory") {

    MasterKey parent = master;
    parent.DeriveSelf(derive_branches);

    ext_pubkey parent_pk =  parent.MakeExtPubKey();

    xonly_pubkey child_pk = MasterKey::DerivePubKey(ChannelKeys::GetStaticSecp256k1Context(), parent_pk, branches[0]);


    ChannelKeys child = parent.Derive(branches, BIP86Tweak::FORCE);

    REQUIRE(child_pk == child.GetLocalPubKey());

}