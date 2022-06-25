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
#include "signer_service.hpp"
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

    SignerService signer0(wallet, 0, ChannelKeys(wallet), N, K);
    SignerService signer1(wallet, 1, ChannelKeys(wallet), N, K);
    SignerService signer2(wallet, 2, ChannelKeys(wallet), N, K);

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

    // Negotiate Aggregated Pubkey
    // TODO: Move before Nonce Commit

    CHECK_NOTHROW(signer0.CommitKeyShares());
    CHECK_NOTHROW(signer1.CommitKeyShares());
    CHECK_NOTHROW(signer2.CommitKeyShares());





    /* Negotiate pubkey
    /*
    /*
    /* Sign
    /*
     */
}