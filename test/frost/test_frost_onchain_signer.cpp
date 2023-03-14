#include <memory>
#include <future>
#include <algorithm>
#include <ranges>

#include "smartinserter.hpp"

#define CATCH_CONFIG_RUNNER
#include "catch/catch.hpp"

#include "util/translation.h"
#include "util/strencodings.h"
#include "script/interpreter.h"
#include "script/standard.h"

#include "common.hpp"
#include "config.hpp"

#include "frost_signer.hpp"

#include "wallet_api.hpp"

#include "generic_service.hpp"
#include "onchain_net_service.hpp"

using namespace l15;
using namespace l15::core;
using namespace l15::p2p;
using namespace l15::service;
using namespace l15::signer_service;
using namespace l15::frost;

std::string configpath;

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

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

struct ThreeSignersTestWrapper {
    WalletApi wallet;
    ChannelKeys keypair0, keypair1, keypair2;
    std::shared_ptr<service::GenericService> service;
    std::shared_ptr<SignerService> signerService;
    std::shared_ptr<l15::p2p::OnChainService> peer0, peer1, peer2;
    std::shared_ptr<FrostSigner> signer0, signer1, signer2;

    ThreeSignersTestWrapper()
            : keypair0(wallet.Secp256k1Context())
            , keypair1(wallet.Secp256k1Context())
            , keypair2(wallet.Secp256k1Context())
            , service(std::make_shared<service::GenericService>(2))
            , signerService(std::make_shared<SignerService>(service))
            , peer0(std::make_shared<l15::p2p::OnChainService>(wallet.Secp256k1Context(), service))
            , peer1(std::make_shared<l15::p2p::OnChainService>(wallet.Secp256k1Context(), service))
            , peer2(std::make_shared<l15::p2p::OnChainService>(wallet.Secp256k1Context(), service))
            , signer0(make_shared<FrostSigner>(keypair0, std::vector<xonly_pubkey>{keypair0.GetLocalPubKey(), keypair1.GetLocalPubKey(), keypair2.GetLocalPubKey()}, signerService, peer0))
            , signer1(make_shared<FrostSigner>(keypair1, std::vector<xonly_pubkey>{keypair0.GetLocalPubKey(), keypair1.GetLocalPubKey(), keypair2.GetLocalPubKey()}, signerService, peer1))
            , signer2(make_shared<FrostSigner>(keypair2, std::vector<xonly_pubkey>{keypair0.GetLocalPubKey(), keypair1.GetLocalPubKey(), keypair2.GetLocalPubKey()}, signerService, peer2))
    {
        signer0->SetErrorHandler([](){
            std::ostringstream stream;
            print_error(stream);
            FAIL(stream.str());
        });

        signer1->SetErrorHandler([](){
            std::ostringstream stream;
            print_error(stream);
            FAIL(stream.str());
        });

        signer2->SetErrorHandler([](){
            std::ostringstream stream;
            print_error(stream);
            FAIL(stream.str());
        });

        peer0->AddPeer(xonly_pubkey(keypair0.GetLocalPubKey()), "tcp://localhost:12000");
        peer0->AddPeer(xonly_pubkey(keypair1.GetLocalPubKey()), "tcp://localhost:12001");
        peer0->AddPeer(xonly_pubkey(keypair2.GetLocalPubKey()), "tcp://localhost:12002");

        peer1->AddPeer(xonly_pubkey(keypair0.GetLocalPubKey()), "tcp://localhost:12000");
        peer1->AddPeer(xonly_pubkey(keypair1.GetLocalPubKey()), "tcp://localhost:12001");
        peer1->AddPeer(xonly_pubkey(keypair2.GetLocalPubKey()), "tcp://localhost:12002");

        peer2->AddPeer(xonly_pubkey(keypair0.GetLocalPubKey()), "tcp://localhost:12000");
        peer2->AddPeer(xonly_pubkey(keypair1.GetLocalPubKey()), "tcp://localhost:12001");
        peer2->AddPeer(xonly_pubkey(keypair2.GetLocalPubKey()), "tcp://localhost:12002");
    }
};

TEST_CASE_METHOD(ThreeSignersTestWrapper, "2-of-3 local")
{
    CHECK_NOTHROW(signer0->Start());
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    CHECK_NOTHROW(signer1->Start());
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    CHECK_NOTHROW(signer2->Start());

    std::promise<xonly_pubkey> aggpk_promise0;
    std::promise<xonly_pubkey> aggpk_promise1;
    std::promise<xonly_pubkey> aggpk_promise2;

    auto aggpk_res0 = aggpk_promise0.get_future();
    auto aggpk_res1 = aggpk_promise1.get_future();
    auto aggpk_res2 = aggpk_promise2.get_future();

    CHECK_NOTHROW(signer0->AggregateKey(cex::make_async_result<const xonly_pubkey&>(
            [](const xonly_pubkey& aggpk, std::promise<xonly_pubkey>&& p){p.set_value(aggpk);},
            [](std::promise<xonly_pubkey>&& p){p.set_exception(std::current_exception());},
            std::move(aggpk_promise0))));

    CHECK_NOTHROW(signer1->AggregateKey(cex::make_async_result<const xonly_pubkey&>(
            [](const xonly_pubkey& aggpk, std::promise<xonly_pubkey>&& p){p.set_value(aggpk);},
            [](std::promise<xonly_pubkey>&& p){p.set_exception(std::current_exception());},
            std::move(aggpk_promise1))));

    CHECK_NOTHROW(signer2->AggregateKey(cex::make_async_result<const xonly_pubkey&>(
            [](const xonly_pubkey& aggpk, std::promise<xonly_pubkey>&& p){p.set_value(aggpk);},
            [](std::promise<xonly_pubkey>&& p){p.set_exception(std::current_exception());},
            std::move(aggpk_promise2))));

    xonly_pubkey aggpk0, aggpk1, aggpk2;

    CHECK_NOTHROW(aggpk0 = aggpk_res0.get());
    CHECK_NOTHROW(aggpk1 = aggpk_res1.get());
    CHECK_NOTHROW(aggpk2 = aggpk_res2.get());

    CHECK(aggpk0.get_vector() == aggpk1.get_vector());
    CHECK(aggpk0.get_vector() == aggpk2.get_vector());

    std::promise<void> nonce_promise0;
    std::promise<void> nonce_promise1;
    std::promise<void> nonce_promise2;

    auto nonce_res0 = nonce_promise0.get_future();
    auto nonce_res1 = nonce_promise1.get_future();
    auto nonce_res2 = nonce_promise2.get_future();

    signer0->CommitNonces(1, cex::make_async_result<void>(
    [](std::promise<void>&& p){p.set_value();},
    [](std::promise<void>&& p){p.set_exception(std::current_exception());},
    move(nonce_promise0)));

    signer1->CommitNonces(1, cex::make_async_result<void>(
    [](std::promise<void>&& p){p.set_value();},
    [](std::promise<void>&& p){p.set_exception(std::current_exception());},
    move(nonce_promise1)));

    signer2->CommitNonces(1, cex::make_async_result<void>(
    [](std::promise<void>&& p){p.set_value();},
    [](std::promise<void>&& p){p.set_exception(std::current_exception());},
    move(nonce_promise2)));

    //std::this_thread::sleep_for(std::chrono::milliseconds(1500));

    CHECK_NOTHROW(nonce_res0.wait());
    CHECK_NOTHROW(nonce_res1.wait());
    CHECK_NOTHROW(nonce_res2.wait());

    std::this_thread::sleep_for(std::chrono::milliseconds(1500));

    bytevector message_data32 {'T','h','i','s',' ','i','s',' ','t','e','s','t',' ','d','a','t','a',' ','t','o',' ','b','e',' ','s','i','g','n','e','d','!','!'};
    REQUIRE(message_data32.size() == 32);

    scalar m(message_data32);

    std::promise<signature> sig_promise0;
    std::promise<signature> sig_promise1;
    std::promise<signature> sig_promise2;

    auto sig_res0 = sig_promise0.get_future();
    auto sig_res1 = sig_promise1.get_future();
    auto sig_res2 = sig_promise2.get_future();

    signer0->Sign(m, m, cex::make_async_result<signature>(
            [](signature sig, std::promise<signature>&& p){p.set_value(sig);},
            [](std::promise<signature>&& p){p.set_exception(std::current_exception());},
            move(sig_promise0)));
    signer1->Sign(m, m, cex::make_async_result<signature>(
            [](signature sig, std::promise<signature>&& p){p.set_value(sig);},
            [](std::promise<signature>&& p){p.set_exception(std::current_exception());},
            move(sig_promise1)));

    signature sig0, sig1;
    CHECK_NOTHROW(sig0 = sig_res0.get());
    CHECK_NOTHROW(sig1 = sig_res1.get());

    std::cout << HexStr(sig0) << std::endl;

    REQUIRE_FALSE(IsZeroArray(sig1));
    CHECK((sig0 == sig1));

    CHECK_NOTHROW(signer0->Verify(m, sig0));

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
}
