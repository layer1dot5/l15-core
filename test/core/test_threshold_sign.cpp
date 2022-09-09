#include <iostream>
#include <filesystem>
#include <cstring>
#include <ranges>
#include <algorithm>
#include <random>
#include <mutex>

#include "smartinserter.hpp"

#define CATCH_CONFIG_RUNNER
#include "catch/catch.hpp"

#include "util/translation.h"
#include "util/strencodings.h"
#include "script/interpreter.h"
#include "script/standard.h"

#include "common.hpp"
#include "config.hpp"
#include "nodehelper.hpp"

#include "signer_api.hpp"
#include "wallet_api.hpp"
#include "chain_api.hpp"
#include "channel_keys.hpp"
#include "exechelper.hpp"

#include "onchain_service.hpp"

#include "local_link.hpp"
#include "time_measure.hpp"
#include "test_suite_node.hpp"

using namespace l15;
using namespace l15::core;
using namespace l15::p2p;
using namespace l15::onchain_service;

namespace rs = std::ranges;
const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;


std::string configpath;

int main(int argc, char* argv[])
{
    Catch::Session session;


    // Build a new parser on top of Catch's
    using namespace Catch::clara;
    auto cli
            = session.cli() // Get Catch's composite command line parser
              | Opt(configpath, "Config path" ) // bind variable to a new option, with a hint string
              ["--config"]    // the option names it will respond to
                      ("Path to node config");

    session.cli( cli );

    // Let Catch (using Clara) parse the command line
    int returnCode = session.applyCommandLine(argc, argv);
    if( returnCode != 0 ) // Indicates a command line error
        return returnCode;

    if(configpath.empty())
    {
        std::cerr << "Config path is not passed!" << std::endl;
        return 1;
    }

    std::filesystem::path p(configpath);
    if(p.is_relative())
    {
        configpath = (std::filesystem::current_path() / p).string();
    }

    return session.run();
}


bool operator== (const std::list<secp256k1_frost_pubnonce>& l1, const std::list<secp256k1_frost_pubnonce>& l2) {
    if (l1.size() == l2.size()) {
        auto i1 = l1.cbegin();
        auto i2 = l2.cbegin();
        for (; i1 != l1.cend(); ++i1, ++i2) {
            if (memcmp(i1->data, i2->data, sizeof(secp256k1_frost_pubnonce::data)) != 0) return false;
        }
        return true;
    }
    else return false;
}

TEST_CASE("2-of-3 local")
{
    const size_t N = 3;
    const size_t K = 2;

    WalletApi wallet;

    // Create peers

    aggregate_key_handler key_hdl = [](SignerApi& s) { s.AggregateKey(); };
    new_sigop_handler new_sigop_hdl = [](SignerApi&, operation_id) { };
    aggregate_sig_handler sig_hdl = [](SignerApi&, operation_id) { };
    error_handler error_hdl = [](Error&& e) { FAIL(e.what()); };

    SignerApi signer0(0, ChannelKeys(wallet.Secp256k1Context()), N, K, new_sigop_hdl, sig_hdl, error_hdl);
    SignerApi signer1(1, ChannelKeys(wallet.Secp256k1Context()), N, K, new_sigop_hdl, sig_hdl, error_hdl);
    SignerApi signer2(2, ChannelKeys(wallet.Secp256k1Context()), N, K, new_sigop_hdl, sig_hdl, error_hdl);

    link_ptr link0 = link_ptr(new LocalLink(signer0));
    link_ptr link1 = link_ptr(new LocalLink(signer1));
    link_ptr link2 = link_ptr(new LocalLink(signer2));

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

    CHECK(xonly_pubkey(wallet.Secp256k1Context(), signer1.Peers()[0].pubkey) == signer0.GetLocalPubKey());
    CHECK(xonly_pubkey(wallet.Secp256k1Context(), signer2.Peers()[0].pubkey) == signer0.GetLocalPubKey());

    CHECK(xonly_pubkey(wallet.Secp256k1Context(), signer0.Peers()[1].pubkey) == signer1.GetLocalPubKey());
    CHECK(xonly_pubkey(wallet.Secp256k1Context(), signer2.Peers()[1].pubkey) == signer1.GetLocalPubKey());

    CHECK(xonly_pubkey(wallet.Secp256k1Context(), signer0.Peers()[2].pubkey) == signer2.GetLocalPubKey());
    CHECK(xonly_pubkey(wallet.Secp256k1Context(), signer1.Peers()[2].pubkey) == signer2.GetLocalPubKey());


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


    REQUIRE_FALSE(ChannelKeys::IsZeroArray(sig1));
    CHECK(sig2 == sig1);
    CHECK(sig0 == sig1);

    CHECK_NOTHROW(signer1.Verify(m, sig2));
    CHECK_NOTHROW(signer2.Verify(m, sig1));
    CHECK_NOTHROW(signer0.Verify(m, sig0));
}

TEST_CASE("500 of 1K local")
{
    const size_t N = 1000;
    const size_t K = 500;

    WalletApi wallet;

    std::vector<std::tuple<std::unique_ptr<SignerApi>, link_ptr>> signers;
    signers.reserve(N);

    aggregate_key_handler key_hdl = [](SignerApi& s) { };
    new_sigop_handler new_sigop_hdl = [](SignerApi&, operation_id) { };
    aggregate_sig_handler sig_hdl = [](SignerApi&, operation_id) { };
    error_handler error_hdl = [&](Error&& e) { FAIL(e.what()); };

    std::ranges::transform(
       std::ranges::common_view(std::views::iota(0) | std::views::take(N)),
       cex::smartinserter(signers, signers.end()),
       [&](int i) {
           std::unique_ptr<SignerApi> signer(
                   new SignerApi(i, ChannelKeys(wallet.Secp256k1Context()), N, K, new_sigop_hdl, sig_hdl, error_hdl));
           link_ptr link = link_ptr(new LocalLink(*signer));
           return std::tuple<std::unique_ptr<SignerApi>, link_ptr>(std::move(signer), std::move(link));
       }
    );

    std::clog << "Signers are initialized" << std::endl;

    {
        TimeMeasure reg_measure("Exchange peer pubkeys");
        std::for_each(std::execution::par_unseq, signers.begin(), signers.end(), [&](auto &si) {
            reg_measure.Measure([&]() {
                for (auto &sj: signers) {
                    if (si != sj) {
                        std::get<0>(si)->AddPeer(std::get<0>(sj)->GetIndex(), std::get<1>(sj));
                    }
                }
                std::get<0>(si)->RegisterToPeers(key_hdl);
                return 0;
            });
        });
        reg_measure.Report(std::clog);
    }


    {
        TimeMeasure distrib_measure("Exchange Key shares");
        std::for_each(signers.begin(), signers.end(), [&](auto& s){
            distrib_measure.Measure([&](){
                std::get<0>(s)->DistributeKeyShares();
                if(std::get<0>(s)->GetIndex() % 100 == 99)
                {
                    std::clog << "Peer " << std::get<0>(s)->GetIndex() << " key share completed" << std::endl;
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
                std::get<0>(si)->AggregateKey();
                return 0;
            });
        });
        keyagg_measure.Report(std::clog);
    }

    const auto& pubkey0 = std::get<0>(signers.front())->GetAggregatedPubKey();
    CHECK_FALSE(ChannelKeys::IsZeroArray(pubkey0));
    for(const auto& si: signers) {
        CHECK(HexStr(pubkey0) == HexStr(std::get<0>(si)->GetAggregatedPubKey()));
    }

    {
        TimeMeasure nonceshare_measure("Commit nonces");
        std::for_each(std::execution::par_unseq, signers.begin(), signers.end(), [&](auto &si) {
            nonceshare_measure.Measure([&]() {
                std::get<0>(si)->CommitNonces(1);
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
                std::get<0>(signers[i])->InitSignature(0);
                return 0;
            });
        });
        initsig_measure.Report(std::clog);
    }

    {
        TimeMeasure preprocsig_measure("Preprocess signature");
        std::for_each(std::execution::par_unseq, actual_signers.begin(), actual_signers.end(), [&](auto &i) {
            preprocsig_measure.Measure([&]() {
                std::get<0>(signers[i])->PreprocessSignature(m, 0);
                return 0;
            });
        });
        preprocsig_measure.Report(std::clog);
    }

    {
        TimeMeasure distribsig_measure("Distribute sig shares");
        std::for_each(std::execution::par_unseq, actual_signers.begin(), actual_signers.end(), [&](auto &i) {
            distribsig_measure.Measure([&]() {
                std::get<0>(signers[i])->DistributeSigShares(0);
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
                signature sig = std::get<0>(signers[i])->AggregateSignature(0);
                {
                    [[maybe_unused]] const std::lock_guard<std::mutex> lock(sig_mutex);
                    final_sigs.emplace_back(std::move(sig));
                }
                return 0;
            });
        });
        aggsig_measure.Report(std::clog);

        for (const auto& sig: final_sigs) {
            CHECK(!ChannelKeys::IsZeroArray(sig));
            CHECK_NOTHROW(std::get<0>(signers.front())->Verify(m, sig));
        }

    }

}

TEST_CASE("50 of 100 on-chain")
{
    const size_t N = 100;
    const size_t K = 50;

    NodeWrapper w;

    std::vector<std::tuple<std::unique_ptr<SignerApi>, link_ptr>> signers;
    signers.reserve(N);

    aggregate_key_handler key_hdl = [](SignerApi& s) { };
    new_sigop_handler new_sigop_hdl = [](SignerApi&, operation_id) { };
    aggregate_sig_handler sig_hdl = [](SignerApi&, operation_id) { };
    error_handler error_hdl = [&](Error&& e) { FAIL(e.what()); };

    std::ranges::transform(
            std::ranges::common_view(std::views::iota(0) | std::views::take(N)),
            cex::smartinserter(signers, signers.end()),
            [&](int i) {
                std::unique_ptr<SignerApi> signer(
                        new SignerApi(i, ChannelKeys(w.wallet.Secp256k1Context()), N, K, new_sigop_hdl, sig_hdl, error_hdl));
                link_ptr link = link_ptr(new LocalLink(*signer));
                return std::tuple<std::unique_ptr<SignerApi>, link_ptr>(std::move(signer), std::move(link));
            }
    );

}
