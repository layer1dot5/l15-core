#include <iostream>
#include <filesystem>
#include <cstring>
#include <ranges>
#include <algorithm>

#include "smartinserter.hpp"

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
namespace rs = std::ranges;
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

    p2p::link_ptr link0 = p2p::link_ptr(new p2p::LocalLink(signer0));
    p2p::link_ptr link1 = p2p::link_ptr(new p2p::LocalLink(signer1));
    p2p::link_ptr link2 = p2p::link_ptr(new p2p::LocalLink(signer2));

    // Connect peers

    signer0.AddPeer(1, link1);
    signer0.AddPeer(2, link2);
    signer1.AddPeer(0, link0);
    signer1.AddPeer(2, link2);
    signer2.AddPeer(0, link0);
    signer2.AddPeer(1, link1);

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

    CHECK_NOTHROW(signer0.InitSignature(0, m, [&](size_t op, signature &&s, std::optional<SignatureError> e) {
        sig0 = s;
        err0 = e;
    }));
    CHECK_NOTHROW(signer1.InitSignature(0, m, [&](size_t op, signature &&s, std::optional<SignatureError> e) {
        sig1 = s;
        err1 = e;
    }));
    CHECK_NOTHROW(signer2.InitSignature(0, m, [&](size_t op, signature &&s, std::optional<SignatureError> e) {
        sig2 = s;
        err2 = e;
    }));

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

TEST_CASE("5k-of-10k")
{
    const size_t N = 1000;
    const size_t K = 500;

    api::WalletApi wallet(api::ChainMode::MODE_REGTEST);


    std::vector<std::tuple<std::unique_ptr<SignerApi>, p2p::link_ptr>> signers;
    signers.reserve(N);

    std::ranges::transform(
       std::ranges::common_view(std::views::iota(0) | std::views::take(N)),
       cex::smartinserter(signers, signers.end()),
       [&](int i) {
           std::unique_ptr<SignerApi> signer(new SignerApi(wallet, i, ChannelKeys(wallet), N, K));
           p2p::link_ptr link = p2p::link_ptr(new p2p::LocalLink(*signer));
           return std::tuple<std::unique_ptr<SignerApi>, p2p::link_ptr>(std::move(signer), std::move(link));
       }
    );

    std::clog << "Signers are initialized" << std::endl;

    CHECK_NOTHROW (
        std::for_each(std::execution::par_unseq, signers.begin(), signers.end(), [&](auto &si) {
            for (auto& sj: signers) {
                if (si != sj) {
                    std::get<0>(si)->AddPeer(std::get<0>(sj)->GetIndex(), std::get<1>(sj));
                }
            }
            std::get<0>(si)->RegisterToPeers();
        })
    );

    std::clog << "Peers are registered" << std::endl;

    CHECK_NOTHROW(std::for_each(signers.begin(), signers.end(), [](auto& s){
        std::get<0>(s)->DistributeKeyShares();
    }));

    std::clog << "Peers keys are shared" << std::endl;


    const auto& pubkey0 = std::get<0>(signers.front())->GetAggregatedPubKey();
    CHECK_FALSE(ChannelKeys::IsZeroArray(pubkey0));

    for (auto& s : signers) {
        CHECK(HexStr(std::get<0>(s)->GetAggregatedPubKey()) == HexStr(pubkey0));
    }

}
