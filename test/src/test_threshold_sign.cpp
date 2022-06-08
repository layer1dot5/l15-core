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

TEST_CASE("2-of-3")
{
    api::WalletApi wallet(api::ChainMode::MODE_REGTEST);

    SignerService signer0(0, ChannelKeys(wallet), 3);
    SignerService signer1(1, ChannelKeys(wallet), 3);
    SignerService signer2(2, ChannelKeys(wallet), 3);

    p2p::link_ptr link1 = p2p::link_ptr(new p2p::LocalLink(signer0));
    p2p::link_ptr link2 = p2p::link_ptr(new p2p::LocalLink(signer1));
    p2p::link_ptr link3 = p2p::link_ptr(new p2p::LocalLink(signer2));

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

    /* serv1.CommitNonces(10);
    /* serv2.CommitNonces(10);
    /* serv3.CommitNonces(10);
    /*
    /*
    /* Negotiate pubkey
    /*
    /*
    /* Sign
    /*
     */
}