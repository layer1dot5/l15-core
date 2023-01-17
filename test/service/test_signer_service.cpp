
#include <memory>
#include <future>
#include <algorithm>

#include "smartinserter.hpp"


#define CATCH_CONFIG_MAIN
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

#include "generic_service.hpp"
#include "signer_service.hpp"

using namespace l15;
using namespace l15::core;
using namespace l15::p2p;
using namespace l15::service;
using namespace l15::signer_service;

TEST_CASE("2-of-3 local")
{
    WalletApi wallet;

    std::shared_ptr<SignerApi> signer0 = std::make_shared<SignerApi>(ChannelKeys(wallet.Secp256k1Context()), 3, 2);
    std::shared_ptr<SignerApi> signer1 = std::make_shared<SignerApi>(ChannelKeys(wallet.Secp256k1Context()), 3, 2);
    std::shared_ptr<SignerApi> signer2 = std::make_shared<SignerApi>(ChannelKeys(wallet.Secp256k1Context()), 3, 2);

    auto service = std::make_shared<service::GenericService>(3);
    signer_service::SignerService signerService(service);

    // Create peers

    error_handler error_hdl = [](Error&& e) {
        FAIL(std::string(e.what()) + ": " + e.details());
    };

    signer0->SetErrorHandler(error_hdl);
    signer1->SetErrorHandler(error_hdl);
    signer2->SetErrorHandler(error_hdl);

    signer0->SetPublisher([&](frost_message_ptr m) {
        service->Serve([=]() {
            signer1->Accept(*m);
            signer2->Accept(*m);
        });
    });
    signer1->SetPublisher([&](frost_message_ptr m) {
        service->Serve([=]() {
            signer0->Accept(*m);
            signer2->Accept(*m);
        });
    });
    signer2->SetPublisher([&](frost_message_ptr m) {
        service->Serve([=]() {
            signer0->Accept(*m);
            signer1->Accept(*m);
        });
    });

    // Connect peers

    signer0->AddPeer(xonly_pubkey(signer1->GetLocalPubKey()), [&](const auto& pk, frost_message_ptr m){ signerService.Accept(signer1, m); });
    signer0->AddPeer(xonly_pubkey(signer2->GetLocalPubKey()), [&](const auto& pk, frost_message_ptr m){ signerService.Accept(signer2, m); });
    signer1->AddPeer(xonly_pubkey(signer0->GetLocalPubKey()), [&](const auto& pk, frost_message_ptr m){ signerService.Accept(signer0, m); });
    signer1->AddPeer(xonly_pubkey(signer2->GetLocalPubKey()), [&](const auto& pk, frost_message_ptr m){ signerService.Accept(signer2, m); });
    signer2->AddPeer(xonly_pubkey(signer0->GetLocalPubKey()), [&](const auto& pk, frost_message_ptr m){ signerService.Accept(signer0, m); });
    signer2->AddPeer(xonly_pubkey(signer1->GetLocalPubKey()), [&](const auto& pk, frost_message_ptr m){ signerService.Accept(signer1, m); });

    auto commkey_promise0 = std::make_shared<std::promise<void>>();
    auto commkey_promise1 = std::make_shared<std::promise<void>>();
    auto commkey_promise2 = std::make_shared<std::promise<void>>();

    auto commkey_res0 = commkey_promise0->get_future();
    auto commkey_res1 = commkey_promise1->get_future();
    auto commkey_res2 = commkey_promise2->get_future();

    signerService.PublishKeyShareCommitment(signer0, [p=commkey_promise0](){p->set_value();}, [p=commkey_promise0](){p->set_exception(std::current_exception());});
    signerService.PublishKeyShareCommitment(signer1, [p=commkey_promise1](){p->set_value();}, [p=commkey_promise1](){p->set_exception(std::current_exception());});
    signerService.PublishKeyShareCommitment(signer2, [p=commkey_promise2](){p->set_value();}, [p=commkey_promise2](){p->set_exception(std::current_exception());});

    CHECK_NOTHROW(commkey_res0.wait());
    CHECK_NOTHROW(commkey_res1.wait());
    CHECK_NOTHROW(commkey_res2.wait());

    auto aggkey_promise0 = std::make_shared<std::promise<const xonly_pubkey&>>();
    auto aggkey_promise1 = std::make_shared<std::promise<const xonly_pubkey&>>();
    auto aggkey_promise2 = std::make_shared<std::promise<const xonly_pubkey&>>();

    auto aggkey_res0 = aggkey_promise0->get_future();
    auto aggkey_res1 = aggkey_promise1->get_future();
    auto aggkey_res2 = aggkey_promise2->get_future();

    signerService.NegotiateKey(signer0, [p=aggkey_promise0](const xonly_pubkey& pk){p->set_value(pk);}, [p=aggkey_promise0](){p->set_exception(std::current_exception());});
    signerService.NegotiateKey(signer1, [p=aggkey_promise1](const xonly_pubkey& pk){p->set_value(pk);}, [p=aggkey_promise1](){p->set_exception(std::current_exception());});
    signerService.NegotiateKey(signer2, [p=aggkey_promise2](const xonly_pubkey& pk){p->set_value(pk);}, [p=aggkey_promise2](){p->set_exception(std::current_exception());});

    xonly_pubkey shared_pk0, shared_pk1, shared_pk2;
    CHECK_NOTHROW(shared_pk0 = aggkey_res0.get());
    CHECK_NOTHROW(shared_pk1 = aggkey_res1.get());
    CHECK_NOTHROW(shared_pk2 = aggkey_res2.get());

    REQUIRE_FALSE(IsZeroArray(shared_pk0));
    CHECK((shared_pk0 == shared_pk1));
    CHECK((shared_pk0 == shared_pk2));

    auto nonce_promise0 = std::make_shared<std::promise<void>>();
    auto nonce_promise1 = std::make_shared<std::promise<void>>();
    auto nonce_promise2 = std::make_shared<std::promise<void>>();

    auto nonce_res0 = nonce_promise0->get_future();
    auto nonce_res1 = nonce_promise1->get_future();
    auto nonce_res2 = nonce_promise2->get_future();

    signerService.PublishNonces(signer0, 2, [p=nonce_promise0](){p->set_value();}, [p=nonce_promise0](){p->set_exception(std::current_exception());});
    signerService.PublishNonces(signer1, 2, [p=nonce_promise1](){p->set_value();}, [p=nonce_promise1](){p->set_exception(std::current_exception());});
    signerService.PublishNonces(signer2, 2, [p=nonce_promise2](){p->set_value();}, [p=nonce_promise2](){p->set_exception(std::current_exception());});

    CHECK_NOTHROW(nonce_res0.wait());
    CHECK_NOTHROW(nonce_res1.wait());
    CHECK_NOTHROW(nonce_res2.wait());

    bytevector message_data32 {'T','h','i','s',' ','i','s',' ','t','e','s','t',' ','d','a','t','a',' ','t','o',' ','b','e',' ','s','i','g','n','e','d','!','!'};
    REQUIRE(message_data32.size() == 32);

    uint256 m(message_data32);

    auto sig_promise0 = std::make_shared<std::promise<signature>>();
    auto sig_promise2 = std::make_shared<std::promise<signature>>();

    auto sign_res0 = sig_promise0->get_future();
    auto sign_res2 = sig_promise2->get_future();

    signerService.Sign(signer0, m, 1, [p=sig_promise0](signature s){p->set_value(s);}, [p=sig_promise0](){p->set_exception(std::current_exception());});
    signerService.Sign(signer2, m, 1, [p=sig_promise2](signature s){p->set_value(s);}, [p=sig_promise2](){p->set_exception(std::current_exception());});

    signature sig0, sig2;
    CHECK_NOTHROW(sig0 = sign_res0.get());
    CHECK_NOTHROW(sig2 = sign_res2.get());

    std::cout << HexStr(sig0) << std::endl;

    REQUIRE_FALSE(IsZeroArray(sig0));
    CHECK((sig0 == sig2));

    CHECK_NOTHROW(signer0->Verify(m, sig0));
}

//TEST_CASE("15-of-30")
//{
//    const size_t N = 30;
//    const size_t K = 15;
//
//    auto service = std::make_shared<service::GenericService>(10);
//    signer_service::SignerService signerService(service);
//    WalletApi wallet;
//
//    // Create peers
//
//    error_handler error_hdl = [](Error&& e) {
//        FAIL(std::string(e.what()) + ": " + e.details());
//    };
//
//    std::vector<std::shared_ptr<SignerApi>> signers;
//    signers.reserve(N);
//
//    std::ranges::transform(
//            std::views::iota(0) | std::views::take(N),
//            cex::smartinserter(signers, signers.end()),
//            [&](int i) {
//                return std::make_shared<SignerApi> (
//                        ChannelKeys(wallet.Secp256k1Context()), N, K, error_hdl);
//            });
//
//
//    std::for_each(signers.begin(), signers.end(), [=, &signerService, &signers](auto& si) {
//        si->SetPublisher([=, &signerService, &signers](frost_message_ptr m) {
//            std::for_each(signers.begin(), signers.end(), [=, &signerService](auto &sj) {
//                if (si != sj)
//                    service->Serve([=, &signerService](){ signerService.Accept(sj->GetLocalPubKey(), m);});
//            });
//        });
//
//        std::for_each(signers.begin(), signers.end(), [=, &signerService](auto& sj){
//            if (si != sj)
//                si->AddPeer(xonly_pubkey(sj->GetLocalPubKey()), [=, &signerService](frost_message_ptr m){
//                    service->Serve([=, &signerService](){ signerService.Accept(sj->GetLocalPubKey(), m);});
//                });
//        });
//
//        signerService.AddSigner(si);
//    });
//
//
//    std::vector<std::future<const xonly_pubkey&>> key_res;
//    std::for_each(signers.begin(), signers.end(), [&signerService, &key_res](auto& si) {
//        key_res.emplace_back(signerService.NegotiateKey(si->GetLocalPubKey()));
//    });
//    CHECK_NOTHROW(
//            std::for_each(key_res.begin(), key_res.end(), [](auto& key) {
//                key.wait();
//            }));
//
//
//    std::vector<std::future<void>> nonce_res;
//    std::for_each(signers.begin(), signers.end(), [&signerService, &nonce_res](auto& si) {
//        nonce_res.emplace_back(signerService.PublishNonces(si->GetLocalPubKey(), 1));
//    });
//    CHECK_NOTHROW(
//            std::for_each(nonce_res.begin(), nonce_res.end(), [](auto& nonce) {
//                nonce.wait();
//            }));
//
//
//    std::string text = "text";
//    uint256 message;
//    CSHA256().Write((unsigned char *) text.data(), text.length()).Finalize(message.data());
//
//
//    std::vector<std::future<signature>> sig_res;
//    std::for_each(signers.begin(), signers.end(), [message, &signerService, &sig_res, &signers](auto& si) {
//        if ((&si - &signers.front()) % 2 == 0)
//            sig_res.emplace_back(signerService.Sign(si->GetLocalPubKey(), message, 0));
//    });
//    CHECK_NOTHROW(
//            std::for_each(sig_res.begin(), sig_res.end(), [message, &signers](auto& sig) {
//                auto s = sig.get();
//                signers.front()->Verify(message, s);
//            }));
//
//}