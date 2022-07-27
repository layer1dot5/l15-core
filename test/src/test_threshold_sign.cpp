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
#include "time_measure.hpp"

using namespace l15;
namespace rs = std::ranges;
const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

TEST_CASE("2-of-3 FROST signature")
{
    const size_t N = 3;
    const size_t K = 2;

    api::WalletApi wallet(api::ChainMode::MODE_REGTEST);

    // Create peers

    aggregate_key_handler key_hdl = [](SignerApi& s) { s.AggregateKey(); };
    new_sigop_handler new_sigop_hdl = [](SignerApi&, operation_id) { };
    aggregate_sig_handler sig_hdl = [](SignerApi&, operation_id) { };
    error_handler error_hdl = [](core::Error&& e) { FAIL(e.what()); };

    SignerApi signer0(wallet, 0, ChannelKeys(wallet), N, K, new_sigop_hdl, sig_hdl, error_hdl);
    SignerApi signer1(wallet, 1, ChannelKeys(wallet), N, K, new_sigop_hdl, sig_hdl, error_hdl);
    SignerApi signer2(wallet, 2, ChannelKeys(wallet), N, K, new_sigop_hdl, sig_hdl, error_hdl);

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


    CHECK_NOTHROW(signer0.RegisterToPeers(key_hdl));
    CHECK_NOTHROW(signer1.RegisterToPeers(key_hdl));
    CHECK_NOTHROW(signer2.RegisterToPeers(key_hdl));

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
    bytevector message_data32 {'T','h','i','s',' ','i','s',' ','t','e','s','t',' ','d','a','t','a',' ','t','o',' ','b','e',' ','s','i','g','n','e','d','!','!'};
    REQUIRE(message_data32.size() == 32);

    uint256 m(message_data32);

    CHECK_NOTHROW(signer0.InitSignature(0, false));
    CHECK_NOTHROW(signer1.InitSignature(0));
    CHECK_NOTHROW(signer2.InitSignature(0));

    signer0.PreprocessSignature(m, 0);
    signer1.PreprocessSignature(m, 0);
    signer2.PreprocessSignature(m, 0);

    CHECK_NOTHROW(signer2.DistributeSigShares(0));
    CHECK_NOTHROW(signer1.DistributeSigShares(0));

    CHECK_NOTHROW(sig1 = signer1.AggregateSignature(0));
    CHECK_NOTHROW(sig2 = signer2.AggregateSignature(0));
    CHECK_NOTHROW(sig0 = signer0.AggregateSignature(0));


    REQUIRE_FALSE(ChannelKeys(wallet).IsZeroArray(sig1));
    CHECK(sig2 == sig1);
    CHECK(sig0 == sig1);

    CHECK_NOTHROW(signer1.Verify(m, sig2));
    CHECK_NOTHROW(signer2.Verify(m, sig1));
    CHECK_NOTHROW(signer0.Verify(m, sig0));
}

//TEST_CASE("Keyshare 1K")
//{
//    const size_t N = 600;
//    const size_t K = 300;
//
//    api::WalletApi wallet(api::ChainMode::MODE_REGTEST);
//
//
//    std::vector<std::tuple<std::unique_ptr<SignerApi>, p2p::link_ptr>> signers;
//    signers.reserve(N);
//
//    error_handler error_handler = [&](core::Error&& e) { FAIL(e.what()); };
//
//    std::ranges::transform(
//       std::ranges::common_view(std::views::iota(0) | std::views::take(N)),
//       cex::smartinserter(signers, signers.end()),
//       [&](int i) {
//           std::unique_ptr<SignerApi> signer(
//                   new SignerApi(wallet, i, ChannelKeys(wallet), N, K, error_handler));
//           p2p::link_ptr link = p2p::link_ptr(new p2p::LocalLink(*signer));
//           return std::tuple<std::unique_ptr<SignerApi>, p2p::link_ptr>(std::move(signer), std::move(link));
//       }
//    );
//
//    std::clog << "Signers are initialized" << std::endl;
//
//    aggregate_key_handler empty_handler = [](SignerApi& s) { };
//
//    TimeMeasure reg_measure("Exchange peer pubkeys");
//
//    std::for_each(std::execution::par_unseq, signers.begin(), signers.end(), [&](auto &si) {
//        reg_measure.Measure([&]() {
//            for(auto &sj: signers)
//            {
//                if(si != sj)
//                {
//                    std::get<0>(si)->AddPeer(std::get<0>(sj)->GetIndex(), std::get<1>(sj));
//                }
//            }
//            std::get<0>(si)->RegisterToPeers(empty_handler);
//            return 0;
//        });
//    });
//
//    reg_measure.Report(std::clog);
//
//
//    TimeMeasure distrib_measure("Exchange Key shares");
//
//    std::for_each(signers.begin(), signers.end(), [&](auto& s){
//        distrib_measure.Measure([&](){
//            std::get<0>(s)->DistributeKeyShares();
//            if(std::get<0>(s)->GetIndex() % 100 == 99)
//            {
//                std::clog << "Peer " << std::get<0>(s)->GetIndex() << " key share completed" << std::endl;
//            }
//            return 0;
//        });
//    });
//
//    distrib_measure.Report(std::clog);
//
//    TimeMeasure keyagg_measure("Aggregate pubkey");
//    std::for_each(std::execution::par_unseq, signers.begin(), signers.end(), [&](auto &si) {
//        keyagg_measure.Measure([&]() {
//            std::get<0>(si)->AggregateKey();
//            return 0;
//        });
//    });
//    keyagg_measure.Report(std::clog);
//
//    const auto& pubkey0 = std::get<0>(signers.front())->GetAggregatedPubKey();
//    CHECK_FALSE(ChannelKeys::IsZeroArray(pubkey0));
//    for(const auto& si: signers)
//    {
//        CHECK(HexStr(pubkey0) == HexStr(std::get<0>(si)->GetAggregatedPubKey()));
//    }
//
//    TimeMeasure nonceshare_measure("Commit nonces");
//    std::for_each(std::execution::par_unseq, signers.begin(), signers.end(), [&](auto &si) {
//        nonceshare_measure.Measure([&]() {
//            std::get<0>(si)->CommitNonces(1);
//            return 0;
//        });
//    });
//    nonceshare_measure.Report(std::clog);
//
//    //CHECK(std::get<0>(signers.front())->Peers()[0].ephemeral_pubkeys.size() == 1);
//
//    bytevector message_data32 {'T','h','i','s',' ','i','s',' ','t','e','s','t',' ','d','a','t','a',' ','t','o',' ','b','e',' ','s','i','g','n','e','d','!','!'};
//    REQUIRE(message_data32.size() == 32);
//    uint256 m(message_data32);
//
//    TimeMeasure initsig_measure("Init signature");
//    std::for_each(std::execution::par_unseq, signers.begin(), signers.end(), [&](auto &si) {
//        initsig_measure.Measure([&]() {
//            std::get<0>(si)->InitSignature(0, m, [](SignerApi& s) {});
//            return 0;
//        });
//    });
//    initsig_measure.Report(std::clog);
//
//    TimeMeasure distribsig_measure("Distribute sig shares");
//    std::for_each(std::execution::par_unseq, signers.begin(), signers.end(), [&](auto &si) {
//        distribsig_measure.Measure([&]() {
//            std::get<0>(si)->DistributeSigShares();
//            return 0;
//        });
//    });
//    distribsig_measure.Report(std::clog);
//
//    TimeMeasure aggsig_measure("Aggregate signature");
//    std::for_each(std::execution::par_unseq, signers.begin(), signers.end(), [&](auto &si) {
//        initsig_measure.Measure([&]() {
//            std::get<0>(si)->AggregateSignature();
//            return 0;
//        });
//    });
//    initsig_measure.Report(std::clog);
//
//}
