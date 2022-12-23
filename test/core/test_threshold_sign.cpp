#include <iostream>
#include <filesystem>
#include <cstring>
#include <ranges>
#include <algorithm>
#include <random>
#include <mutex>

#include "smartinserter.hpp"

#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"

#include "util/translation.h"
#include "util/strencodings.h"

#include "common.hpp"

#include "signer_api.hpp"
#include "wallet_api.hpp"
#include "chain_api.hpp"
#include "channel_keys.hpp"
#include "generic_service.hpp"


#include "time_measure.hpp"

using namespace l15;
using namespace l15::core;
using namespace l15::p2p;

namespace rs = std::ranges;

bool operator== (const  secp256k1_frost_pubnonce& l1, const  secp256k1_frost_pubnonce& l2) {
    return memcmp(l1.data, l2.data, sizeof(secp256k1_frost_pubnonce::data)) == 0;
}

TEST_CASE("2-of-3 local")
{
    const size_t N = 3;
    const size_t K = 2;

    WalletApi wallet;

    // Create peers

    general_handler key_hdl = []() {  };
    sigop_handler new_sigop_hdl = [](operation_id) { };
    sigop_handler sig_hdl = [](operation_id) { };
    error_handler error_hdl = [](Error&& e) { FAIL(std::string(e.what()) + ": " + e.details()); };

    SignerApi signer0(ChannelKeys(wallet.Secp256k1Context()), N, K);
    SignerApi signer1(ChannelKeys(wallet.Secp256k1Context()), N, K);
    SignerApi signer2(ChannelKeys(wallet.Secp256k1Context()), N, K);

    signer0.SetErrorHandler(error_hdl);
    signer1.SetErrorHandler(error_hdl);
    signer2.SetErrorHandler(error_hdl);

    signer0.SetPublisher([&](frost_message_ptr&& m) {
        signer1.Accept(*m);
        signer2.Accept(*m);
    });
    signer1.SetPublisher([&](frost_message_ptr&& m) {
        signer0.Accept(*m);
        signer2.Accept(*m);
    });
    signer2.SetPublisher([&](frost_message_ptr&& m) {
        signer0.Accept(*m);
        signer1.Accept(*m);
    });

    // Connect peers

    signer0.AddPeer(xonly_pubkey(signer1.GetLocalPubKey()), [&signer1](const auto& pk, auto m){signer1.Accept(*m);});
    signer0.AddPeer(xonly_pubkey(signer2.GetLocalPubKey()), [&signer2](const auto& pk, auto m){signer2.Accept(*m);});
    signer1.AddPeer(xonly_pubkey(signer0.GetLocalPubKey()), [&signer0](const auto& pk, auto m){signer0.Accept(*m);});
    signer1.AddPeer(xonly_pubkey(signer2.GetLocalPubKey()), [&signer2](const auto& pk, auto m){signer2.Accept(*m);});
    signer2.AddPeer(xonly_pubkey(signer0.GetLocalPubKey()), [&signer0](const auto& pk, auto m){signer0.Accept(*m);});
    signer2.AddPeer(xonly_pubkey(signer1.GetLocalPubKey()), [&signer1](const auto& pk, auto m){signer1.Accept(*m);});


    // Negotiate Aggregated Pubkey

    CHECK_NOTHROW(signer0.DistributeKeyShares(key_hdl));
    CHECK_NOTHROW(signer1.DistributeKeyShares(key_hdl));
    CHECK_NOTHROW(signer2.DistributeKeyShares(key_hdl));

    CHECK_NOTHROW(signer0.AggregateKey());
    CHECK_NOTHROW(signer1.AggregateKey());
    CHECK_NOTHROW(signer2.AggregateKey());

    CHECK((signer0.GetAggregatedPubKey() == signer1.GetAggregatedPubKey()));
    CHECK((signer0.GetAggregatedPubKey() == signer2.GetAggregatedPubKey()));


    //Commit Nonces

    CHECK_NOTHROW(signer0.CommitNonces(3));
    CHECK_NOTHROW(signer1.CommitNonces(3));
    CHECK_NOTHROW(signer2.CommitNonces(3));

    CHECK(signer0.GetNonceCount() == 3);
    CHECK(signer1.GetNonceCount() == 3);
    CHECK(signer2.GetNonceCount() == 3);

    CHECK(signer0.Peers().at(signer0.GetLocalPubKey()).ephemeral_pubkeys.size() == 3);
    CHECK(signer0.Peers().at(signer1.GetLocalPubKey()).ephemeral_pubkeys.size() == 3);
    CHECK(signer0.Peers().at(signer2.GetLocalPubKey()).ephemeral_pubkeys.size() == 3);

    CHECK(signer1.Peers().at(signer0.GetLocalPubKey()).ephemeral_pubkeys.size() == 3);
    CHECK(signer1.Peers().at(signer1.GetLocalPubKey()).ephemeral_pubkeys.size() == 3);
    CHECK(signer1.Peers().at(signer2.GetLocalPubKey()).ephemeral_pubkeys.size() == 3);

    CHECK(signer2.Peers().at(signer0.GetLocalPubKey()).ephemeral_pubkeys.size() == 3);
    CHECK(signer2.Peers().at(signer1.GetLocalPubKey()).ephemeral_pubkeys.size() == 3);
    CHECK(signer2.Peers().at(signer2.GetLocalPubKey()).ephemeral_pubkeys.size() == 3);

    CHECK(signer0.Peers().at(signer0.GetLocalPubKey()).ephemeral_pubkeys == signer1.Peers().at(signer0.GetLocalPubKey()).ephemeral_pubkeys);
    CHECK(signer0.Peers().at(signer0.GetLocalPubKey()).ephemeral_pubkeys == signer2.Peers().at(signer0.GetLocalPubKey()).ephemeral_pubkeys);

    CHECK(signer0.Peers().at(signer1.GetLocalPubKey()).ephemeral_pubkeys == signer1.Peers().at(signer1.GetLocalPubKey()).ephemeral_pubkeys);
    CHECK(signer0.Peers().at(signer1.GetLocalPubKey()).ephemeral_pubkeys == signer2.Peers().at(signer1.GetLocalPubKey()).ephemeral_pubkeys);

    CHECK(signer0.Peers().at(signer2.GetLocalPubKey()).ephemeral_pubkeys == signer1.Peers().at(signer2.GetLocalPubKey()).ephemeral_pubkeys);
    CHECK(signer0.Peers().at(signer2.GetLocalPubKey()).ephemeral_pubkeys == signer2.Peers().at(signer2.GetLocalPubKey()).ephemeral_pubkeys);


    // Sign

    signature sig0, sig1, sig2;
    bytevector message_data32 {'T','h','i','s',' ','i','s',' ','t','e','s','t',' ','d','a','t','a',' ','t','o',' ','b','e',' ','s','i','g','n','e','d','!','!'};
    REQUIRE(message_data32.size() == 32);

    uint256 m(message_data32);

    CHECK_NOTHROW(signer0.InitSignature(0, make_callable_with_signer(new_sigop_hdl, 0), make_callable_with_signer(sig_hdl, 0), false));
    CHECK_NOTHROW(signer1.InitSignature(0, make_callable_with_signer(new_sigop_hdl, 0), make_callable_with_signer(sig_hdl, 0)));
    CHECK_NOTHROW(signer2.InitSignature(0, make_callable_with_signer(new_sigop_hdl, 0), make_callable_with_signer(sig_hdl, 0)));

    CHECK_NOTHROW(signer0.PreprocessSignature(m, 0));
    CHECK_NOTHROW(signer1.PreprocessSignature(m, 0));
    CHECK_NOTHROW(signer2.PreprocessSignature(m, 0));

    CHECK_NOTHROW(signer2.DistributeSigShares(0));
    CHECK_NOTHROW(signer1.DistributeSigShares(0));

    CHECK_NOTHROW(sig1 = signer1.AggregateSignature(0));
    CHECK_NOTHROW(sig2 = signer2.AggregateSignature(0));
    CHECK_NOTHROW(sig0 = signer0.AggregateSignature(0));


    REQUIRE_FALSE(IsZeroArray(sig1));
    CHECK((sig2 == sig1));
    CHECK((sig0 == sig1));

    CHECK_NOTHROW(signer1.Verify(m, sig2));
    CHECK_NOTHROW(signer2.Verify(m, sig1));
    CHECK_NOTHROW(signer0.Verify(m, sig0));
}

TEST_CASE("Try sign without pubnonce")
{
    const size_t N = 3;
    const size_t K = 2;

    WalletApi wallet;

    // Create peers

    general_handler key_hdl = []() {  };
    sigop_handler new_sigop_hdl = [](operation_id) { };
    sigop_handler sig_hdl = [](operation_id) { };
    error_handler error_hdl = [](Error&& e) {
        if (std::string("OutOfOrderMessageError") == e.what() || std::string(e.details()).starts_with("SignatureCommitment")) {
        }
        else {
            FAIL(std::string(e.what()) + ": " + e.details());
        }
    };

    SignerApi signer0(ChannelKeys(wallet.Secp256k1Context()), N, K);
    SignerApi signer1(ChannelKeys(wallet.Secp256k1Context()), N, K);
    SignerApi signer2(ChannelKeys(wallet.Secp256k1Context()), N, K);

    signer0.SetErrorHandler(error_hdl);
    signer1.SetErrorHandler(error_hdl);
    signer2.SetErrorHandler(error_hdl);

    signer0.SetPublisher([&](frost_message_ptr&& m) {
        signer1.Accept(*m);
        signer2.Accept(*m);
    });
    signer1.SetPublisher([&](frost_message_ptr&& m) {
        signer0.Accept(*m);
        signer2.Accept(*m);
    });
    signer2.SetPublisher([&](frost_message_ptr&& m) {
        signer0.Accept(*m);
        signer1.Accept(*m);
    });

    // Connect peers

    signer0.AddPeer(xonly_pubkey(signer1.GetLocalPubKey()), [&signer1](const auto& pk, auto m){signer1.Accept(*m);});
    signer0.AddPeer(xonly_pubkey(signer2.GetLocalPubKey()), [&signer2](const auto& pk, auto m){signer2.Accept(*m);});
    signer1.AddPeer(xonly_pubkey(signer0.GetLocalPubKey()), [&signer0](const auto& pk, auto m){signer0.Accept(*m);});
    signer1.AddPeer(xonly_pubkey(signer2.GetLocalPubKey()), [&signer2](const auto& pk, auto m){signer2.Accept(*m);});
    signer2.AddPeer(xonly_pubkey(signer0.GetLocalPubKey()), [&signer0](const auto& pk, auto m){signer0.Accept(*m);});
    signer2.AddPeer(xonly_pubkey(signer1.GetLocalPubKey()), [&signer1](const auto& pk, auto m){signer1.Accept(*m);});


    // Negotiate Aggregated Pubkey

    CHECK_NOTHROW(signer0.CommitKeyShares());
    CHECK_NOTHROW(signer1.CommitKeyShares());
    CHECK_NOTHROW(signer2.CommitKeyShares());

    CHECK_NOTHROW(signer0.DistributeKeyShares(key_hdl));
    CHECK_NOTHROW(signer1.DistributeKeyShares(key_hdl));
    CHECK_NOTHROW(signer2.DistributeKeyShares(key_hdl));

    CHECK_NOTHROW(signer0.AggregateKey());
    CHECK_NOTHROW(signer1.AggregateKey());
    CHECK_NOTHROW(signer2.AggregateKey());

    CHECK((signer0.GetAggregatedPubKey() == signer1.GetAggregatedPubKey()));
    CHECK((signer0.GetAggregatedPubKey() == signer2.GetAggregatedPubKey()));


    //Commit Nonces

    CHECK_NOTHROW(signer0.CommitNonces(3));
    CHECK_NOTHROW(signer1.CommitNonces(3));
    //CHECK_NOTHROW(signer2.CommitNonces(3));

    CHECK(signer0.GetNonceCount() == 3);
    CHECK(signer1.GetNonceCount() == 3);
    CHECK(signer2.GetNonceCount() == 0);

    CHECK(signer0.Peers().at(signer0.GetLocalPubKey()).ephemeral_pubkeys.size() == 3);
    CHECK(signer0.Peers().at(signer1.GetLocalPubKey()).ephemeral_pubkeys.size() == 3);
    CHECK(signer0.Peers().at(signer2.GetLocalPubKey()).ephemeral_pubkeys.empty());

    CHECK(signer1.Peers().at(signer0.GetLocalPubKey()).ephemeral_pubkeys.size() == 3);
    CHECK(signer1.Peers().at(signer1.GetLocalPubKey()).ephemeral_pubkeys.size() == 3);
    CHECK(signer1.Peers().at(signer2.GetLocalPubKey()).ephemeral_pubkeys.empty());

    CHECK(signer2.Peers().at(signer0.GetLocalPubKey()).ephemeral_pubkeys.size() == 3);
    CHECK(signer2.Peers().at(signer1.GetLocalPubKey()).ephemeral_pubkeys.size() == 3);
    CHECK(signer2.Peers().at(signer2.GetLocalPubKey()).ephemeral_pubkeys.empty());

    CHECK(signer0.Peers().at(signer0.GetLocalPubKey()).ephemeral_pubkeys == signer1.Peers().at(signer0.GetLocalPubKey()).ephemeral_pubkeys);
    CHECK(signer0.Peers().at(signer0.GetLocalPubKey()).ephemeral_pubkeys == signer2.Peers().at(signer0.GetLocalPubKey()).ephemeral_pubkeys);

    CHECK(signer0.Peers().at(signer1.GetLocalPubKey()).ephemeral_pubkeys == signer1.Peers().at(signer1.GetLocalPubKey()).ephemeral_pubkeys);
    CHECK(signer0.Peers().at(signer1.GetLocalPubKey()).ephemeral_pubkeys == signer2.Peers().at(signer1.GetLocalPubKey()).ephemeral_pubkeys);

    CHECK(signer0.Peers().at(signer2.GetLocalPubKey()).ephemeral_pubkeys == signer1.Peers().at(signer2.GetLocalPubKey()).ephemeral_pubkeys);
    CHECK(signer0.Peers().at(signer2.GetLocalPubKey()).ephemeral_pubkeys == signer2.Peers().at(signer2.GetLocalPubKey()).ephemeral_pubkeys);


    // Sign

    signature sig0, sig1, sig2;
    bytevector message_data32 {'T','h','i','s',' ','i','s',' ','t','e','s','t',' ','d','a','t','a',' ','t','o',' ','b','e',' ','s','i','g','n','e','d','!','!'};
    REQUIRE(message_data32.size() == 32);

    uint256 m(message_data32);

    CHECK_NOTHROW(signer0.InitSignature(0, make_callable_with_signer(new_sigop_hdl, 0), make_callable_with_signer(sig_hdl, 0), false));
    CHECK_NOTHROW(signer1.InitSignature(0, make_callable_with_signer(new_sigop_hdl, 0), make_callable_with_signer(sig_hdl, 0)));
    CHECK_NOTHROW(signer2.InitSignature(0, make_callable_with_signer(new_sigop_hdl, 0), make_callable_with_signer(sig_hdl, 0)));

    REQUIRE_THROWS(signer0.PreprocessSignature(m, 0));
    REQUIRE_THROWS(signer1.PreprocessSignature(m, 0));
    REQUIRE_THROWS(signer2.PreprocessSignature(m, 0));

}

TEST_CASE("500 of 1K local")
{
    const size_t N = 100;
    const size_t K = 50;

    WalletApi wallet;

    std::vector<std::unique_ptr<SignerApi>> signers;
    signers.reserve(N);

    general_handler key_hdl = []() { };
    sigop_handler new_sigop_hdl = [](operation_id) { };
    sigop_handler sig_hdl = [](operation_id) { };
    error_handler error_hdl = [&](Error&& e) {
        FAIL(std::string(e.what()) + ": " + e.details());
    };

    std::ranges::transform(
       std::views::iota(0) | std::views::take(N),
       cex::smartinserter(signers, signers.end()),
       [&](int i) {
           auto s = std::make_unique<SignerApi> (
                   ChannelKeys(wallet.Secp256k1Context()), N, K);
           s->SetErrorHandler(error_hdl);
           return s;
       }
    );

    frost_publish_handler publisher = [&signers](frost_message_ptr m) {
        std::for_each(std::execution::par_unseq, signers.begin(), signers.end(), [&m](const auto& s){
            s->Accept(*m);
        });
    };

    std::clog << "Signers are initialized" << std::endl;

    {
        TimeMeasure reg_measure("Exchange peer pubkeys");
        std::for_each(std::execution::par_unseq, signers.begin(), signers.end(), [&](auto &si) {
            reg_measure.Measure([&]() {
                si->SetPublisher(publisher);
                for (auto &sj: signers) {
                    if (si != sj) {
                        si->AddPeer(xonly_pubkey(sj->GetLocalPubKey()), [&sj](const auto& pk, auto m){sj->Accept(*m);});
                    }
                }
                return 0;
            });
        });
        reg_measure.Report(std::clog);
    }

    {
        TimeMeasure distrib_measure("Commit Key shares");
        size_t i = 0;
        std::for_each(signers.begin(), signers.end(), [&](auto& s){
            distrib_measure.Measure([&](){
                ++i;
                s->CommitKeyShares();
                if(i % 100 == 99)
                {
                    std::clog << "Peer " << i << " commited key share" << std::endl;
                }
                return 0;
            });
        });
        distrib_measure.Report(std::clog);
    }

    {
        TimeMeasure distrib_measure("Exchange Key shares");
        size_t i = 0;
        std::for_each(signers.begin(), signers.end(), [&](auto& s){
            distrib_measure.Measure([&](){
                ++i;
                s->DistributeKeyShares(key_hdl);
                if(i % 100 == 99)
                {
                    std::clog << "Peer " << i << " key share completed" << std::endl;
                }
                return 0;
            });
        });
        distrib_measure.Report(std::clog);
    }

    {
        TimeMeasure keyagg_measure("Aggregate pubkey");
        std::for_each(std::execution::par_unseq, signers.begin(), signers.end(), [&](auto &si) {
            keyagg_measure.Measure([&]() {
                si->AggregateKey();
                return 0;
            });
        });
        keyagg_measure.Report(std::clog);
    }

    const auto& pubkey0 = signers.front()->GetAggregatedPubKey();
    CHECK_FALSE(IsZeroArray(pubkey0));
    for(const auto& si: signers) {
        CHECK(HexStr(pubkey0) == HexStr(si->GetAggregatedPubKey()));
    }

    {
        TimeMeasure nonceshare_measure("Commit nonces");
        std::for_each(std::execution::par_unseq, signers.begin(), signers.end(), [&](auto &si) {
            nonceshare_measure.Measure([&]() {
                si->CommitNonces(1);
                return 0;
            });
        });
        nonceshare_measure.Report(std::clog);
    }

    //CHECK(std::get<0>(signers.front())->Peers()[0].ephemeral_pubkeys.size() == 1);

    bytevector message_data32 {'T','h','i','s',' ','i','s',' ','t','e','s','t',' ','d','a','t','a',' ','t','o',' ','b','e',' ','s','i','g','n','e','d','!','!'};
    REQUIRE(message_data32.size() == 32);
    uint256 m(message_data32);

    std::set<size_t> actual_signers;

    std::random_device r;
    std::default_random_engine e1(r());
    std::uniform_int_distribution<size_t> uniform_dist(0, N-1);

    while (actual_signers.size() < K) {
        actual_signers.emplace(uniform_dist(e1));
    }

    {
        TimeMeasure initsig_measure("Init signature");
        std::for_each(std::execution::par_unseq, actual_signers.begin(), actual_signers.end(), [&](auto &i) {
            initsig_measure.Measure([&]() {
                signers[i]->InitSignature(0, make_callable_with_signer(new_sigop_hdl, 0), make_callable_with_signer(sig_hdl, 0));
                return 0;
            });
        });
        initsig_measure.Report(std::clog);
    }

    {
        TimeMeasure preprocsig_measure("Preprocess signature");
        std::for_each(std::execution::par_unseq, actual_signers.begin(), actual_signers.end(), [&](auto &i) {
            preprocsig_measure.Measure([&]() {
                signers[i]->PreprocessSignature(m, 0);
                return 0;
            });
        });
        preprocsig_measure.Report(std::clog);
    }

    {
        TimeMeasure distribsig_measure("Distribute sig shares");
        std::for_each(std::execution::par_unseq, actual_signers.begin(), actual_signers.end(), [&](auto &i) {
            distribsig_measure.Measure([&]() {
                signers[i]->DistributeSigShares(0);
                return 0;
            });
        });
        distribsig_measure.Report(std::clog);
    }

    {
        std::mutex sig_mutex;
        std::list<signature> final_sigs;
        TimeMeasure aggsig_measure("Aggregate signature");
        std::for_each(std::execution::par_unseq, actual_signers.begin(), actual_signers.end(), [&](auto &i) {
            aggsig_measure.Measure([&]() {
                signature sig = signers[i]->AggregateSignature(0);
                {
                    [[maybe_unused]] const std::lock_guard<std::mutex> lock(sig_mutex);
                    final_sigs.emplace_back(std::move(sig));
                }
                return 0;
            });
        });
        aggsig_measure.Report(std::clog);

        size_t i = 0;
        for (const auto& sig: final_sigs) {
            std::clog << "sig " << i++ << ": " << hex(sig) << std::endl;
            CHECK(!IsZeroArray(sig));
            CHECK_NOTHROW(signers.front()->Verify(m, sig));
        }

    }

}

//TEST_CASE("50 of 100 on-chain")
//{
//    const size_t N = 100;
//    const size_t K = 50;
//
//    NodeWrapper w;
//
//    std::vector<std::tuple<std::unique_ptr<SignerApi>, link_ptr>> signers;
//    signers.reserve(N);
//
//    general_handler key_hdl = [](SignerApi& s) { };
//    new_sigop_handler new_sigop_hdl = [](SignerApi&, operation_id) { };
//    aggregate_sig_handler sig_hdl = [](SignerApi&, operation_id) { };
//    error_handler error_hdl = [&](Error&& e) { FAIL(e.what()); };
//
//    std::ranges::transform(
//            std::ranges::common_view(std::views::iota(0) | std::views::take(N)),
//            cex::smartinserter(signers, signers.end()),
//            [&](int i) {
//                std::unique_ptr<SignerApi> signer(
//                        new SignerApi(ChannelKeys(w.wallet.Secp256k1Context()), N, K, new_sigop_hdl, sig_hdl, error_hdl));
//                link_ptr link = link_ptr(new LocalLink(*signer));
//                return std::tuple<std::unique_ptr<SignerApi>, link_ptr>(std::move(signer), std::move(link));
//            }
//    );
//
//}
