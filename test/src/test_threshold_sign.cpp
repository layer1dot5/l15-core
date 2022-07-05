#include <iostream>
#include <filesystem>
#include <cstring>

#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"

#include "util/translation.h"
#include "util/strencodings.h"
#include "script/interpreter.h"
#include "script/standard.h"

#include "common.hpp"
#include "signer_api.hpp"
#include "wallet_api.hpp"
#include "channel_keys.hpp"

#include "local_link.hpp"

using namespace l15;
const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

TEST_CASE("2-of-3 FROST signature")
{
    const size_t N = 3;
    const size_t K = 2;

    api::WalletApi wallet(api::ChainMode::MODE_REGTEST);

    // Create peers

    SignerApi signer0(wallet, 0, ChannelKeys(wallet), N, K);
    SignerApi signer1(wallet, 1, ChannelKeys(wallet), N, K);
    SignerApi signer2(wallet, 2, ChannelKeys(wallet), N, K);

    p2p::link_ptr link1 = p2p::link_ptr(new p2p::LocalLink(signer0));
    p2p::link_ptr link2 = p2p::link_ptr(new p2p::LocalLink(signer1));
    p2p::link_ptr link3 = p2p::link_ptr(new p2p::LocalLink(signer2));

    // Connect peers

    signer0.AddPeer(1, link2);
    signer0.AddPeer(2, link3);
    signer1.AddPeer(0, link1);
    signer1.AddPeer(2, link3);
    signer2.AddPeer(0, link1);
    signer2.AddPeer(1, link2);

    CHECK_NOTHROW(signer0.RegisterToPeers());
    CHECK_NOTHROW(signer1.RegisterToPeers());
    CHECK_NOTHROW(signer2.RegisterToPeers());

    CHECK(signer1.Peers()[0].pubkey == signer0.GetLocalPubKey());
    CHECK(signer2.Peers()[0].pubkey == signer0.GetLocalPubKey());

    CHECK(signer0.Peers()[1].pubkey == signer1.GetLocalPubKey());
    CHECK(signer2.Peers()[1].pubkey == signer1.GetLocalPubKey());

    CHECK(signer0.Peers()[2].pubkey == signer2.GetLocalPubKey());
    CHECK(signer1.Peers()[2].pubkey == signer2.GetLocalPubKey());


    // Negotiate Aggregated Pubkey

    CHECK_NOTHROW(signer0.DistributeKeyShares());
    CHECK_NOTHROW(signer1.DistributeKeyShares());
    CHECK_NOTHROW(signer2.DistributeKeyShares());

    CHECK(signer0.GetAggregatedPubKey() == signer1.GetAggregatedPubKey());
    CHECK(signer0.GetAggregatedPubKey() == signer2.GetAggregatedPubKey());


    //Commit Nonces

    CHECK_NOTHROW(signer0.CommitNonces(3));
    CHECK_NOTHROW(signer1.CommitNonces(3));
    CHECK_NOTHROW(signer2.CommitNonces(3));

    CHECK(signer0.GetNonceCount() == 3);
    CHECK(signer1.GetNonceCount() == 3);
    CHECK(signer2.GetNonceCount() == 3);

    CHECK(signer0.Peers()[0].ephemeral_pubkeys.size() == 3);
    CHECK(signer0.Peers()[1].ephemeral_pubkeys.size() == 3);
    CHECK(signer0.Peers()[2].ephemeral_pubkeys.size() == 3);

    CHECK(signer1.Peers()[0].ephemeral_pubkeys.size() == 3);
    CHECK(signer1.Peers()[1].ephemeral_pubkeys.size() == 3);
    CHECK(signer1.Peers()[2].ephemeral_pubkeys.size() == 3);

    CHECK(signer2.Peers()[0].ephemeral_pubkeys.size() == 3);
    CHECK(signer2.Peers()[1].ephemeral_pubkeys.size() == 3);
    CHECK(signer2.Peers()[2].ephemeral_pubkeys.size() == 3);

    CHECK(signer0.Peers()[0].ephemeral_pubkeys == signer1.Peers()[0].ephemeral_pubkeys);
    CHECK(signer0.Peers()[0].ephemeral_pubkeys == signer2.Peers()[0].ephemeral_pubkeys);

    CHECK(signer0.Peers()[1].ephemeral_pubkeys == signer1.Peers()[1].ephemeral_pubkeys);
    CHECK(signer0.Peers()[1].ephemeral_pubkeys == signer2.Peers()[1].ephemeral_pubkeys);

    CHECK(signer0.Peers()[2].ephemeral_pubkeys == signer1.Peers()[2].ephemeral_pubkeys);
    CHECK(signer0.Peers()[2].ephemeral_pubkeys == signer2.Peers()[2].ephemeral_pubkeys);


    // Sign

    signature sig0, sig1, sig2;
    std::optional<SignatureError> err0, err1, err2;
    bytevector message_data32 {'T','h','i','s',' ','i','s',' ','t','e','s','t',' ','d','a','t','a',' ','t','o',' ','b','e',' ','s','i','g','n','e','d','!','!'};
    REQUIRE(message_data32.size() == 32);

    uint256 m(message_data32);

    signer0.InitSignature(0, m, [&](size_t op, signature &&s, std::optional<SignatureError> e) {
        sig0 = s;
        err0 = e;
    });
    signer1.InitSignature(0, m, [&](size_t op, signature &&s, std::optional<SignatureError> e) {
        sig1 = s;
        err1 = e;
    });
    signer2.InitSignature(0, m, [&](size_t op, signature &&s, std::optional<SignatureError> e) {
        sig2 = s;
        err2 = e;
    });

    CHECK_NOTHROW(signer0.DistributeSigShares());
    CHECK_NOTHROW(signer1.DistributeSigShares());

    // This combination does not work due to bug in the FROST lib
    //CHECK_NOTHROW(signer2.DistributeSigShares());
    //CHECK_NOTHROW(signer1.DistributeSigShares());

    CHECK_FALSE(err0.has_value());
    CHECK_FALSE(err1.has_value());
    CHECK_FALSE(err2.has_value());

    REQUIRE_FALSE(ChannelKeys(wallet).IsZeroArray(sig0));
    CHECK(sig0 == sig1);
    CHECK(sig0 == sig2);

    CHECK_NOTHROW(signer0.Verify(m, sig0));
    CHECK_NOTHROW(signer1.Verify(m, sig0));
    CHECK_NOTHROW(signer2.Verify(m, sig0));
}