
#include <memory>
#include <future>
#include <algorithm>


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
    auto service = std::make_shared<service::GenericService>(3);
    signer_service::SignerService signerService(service);
    WalletApi wallet;

    // Create peers

    error_handler error_hdl = [](Error&& e) {
        FAIL(std::string(e.what()) + ": " + e.details());
    };

    std::shared_ptr<SignerApi> signer0 = std::make_shared<SignerApi>(ChannelKeys(wallet.Secp256k1Context()), 3, 2, error_hdl);
    std::shared_ptr<SignerApi> signer1 = std::make_shared<SignerApi>(ChannelKeys(wallet.Secp256k1Context()), 3, 2, error_hdl);
    std::shared_ptr<SignerApi> signer2 = std::make_shared<SignerApi>(ChannelKeys(wallet.Secp256k1Context()), 3, 2, error_hdl);

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

    signer0->AddPeer(xonly_pubkey(signer1->GetLocalPubKey()), [&](frost_message_ptr m){ service->Serve([=]() { signer1->Accept(*m); }); });
    signer0->AddPeer(xonly_pubkey(signer2->GetLocalPubKey()), [&](frost_message_ptr m){ service->Serve([=]() { signer2->Accept(*m); }); });
    signer1->AddPeer(xonly_pubkey(signer0->GetLocalPubKey()), [&](frost_message_ptr m){ service->Serve([=]() { signer0->Accept(*m); }); });
    signer1->AddPeer(xonly_pubkey(signer2->GetLocalPubKey()), [&](frost_message_ptr m){ service->Serve([=]() { signer2->Accept(*m); }); });
    signer2->AddPeer(xonly_pubkey(signer0->GetLocalPubKey()), [&](frost_message_ptr m){ service->Serve([=]() { signer0->Accept(*m); }); });
    signer2->AddPeer(xonly_pubkey(signer1->GetLocalPubKey()), [&](frost_message_ptr m){ service->Serve([=]() { signer1->Accept(*m); }); });

    signerService.AddSigner(signer0);
    signerService.AddSigner(signer1);
    signerService.AddSigner(signer2);

    auto aggkey_res0 = signerService.NegotiateKey(signer0->GetLocalPubKey());
    auto aggkey_res1 = signerService.NegotiateKey(signer1->GetLocalPubKey());
    auto aggkey_res2 = signerService.NegotiateKey(signer2->GetLocalPubKey());

    xonly_pubkey shared_pk0, shared_pk1, shared_pk2;
    CHECK_NOTHROW(shared_pk0 = aggkey_res0.get());
    CHECK_NOTHROW(shared_pk1 = aggkey_res1.get());
    CHECK_NOTHROW(shared_pk2 = aggkey_res2.get());

    auto nonce_res0 = signerService.PublishNonces(signer0->GetLocalPubKey(), 2);
    auto nonce_res1 = signerService.PublishNonces(signer1->GetLocalPubKey(), 2);
    auto nonce_res2 = signerService.PublishNonces(signer2->GetLocalPubKey(), 2);

    CHECK_NOTHROW(nonce_res0.wait());
    CHECK_NOTHROW(nonce_res1.wait());
    CHECK_NOTHROW(nonce_res2.wait());

    bytevector message_data32 {'T','h','i','s',' ','i','s',' ','t','e','s','t',' ','d','a','t','a',' ','t','o',' ','b','e',' ','s','i','g','n','e','d','!','!'};
    REQUIRE(message_data32.size() == 32);

    uint256 m(message_data32);

    auto sign_res0 = signerService.Sign(signer0->GetLocalPubKey(), m, 0);
    auto sign_res1 = signerService.Sign(signer1->GetLocalPubKey(), m, 0);

    signature sig0, sig1;
    CHECK_NOTHROW(sig0 = sign_res0.get());
    CHECK_NOTHROW(sig1 = sign_res1.get());

    std::cout << HexStr(sig0) << std::endl;

    REQUIRE_FALSE(IsZeroArray(sig1));
    CHECK((sig0 == sig1));

    CHECK_NOTHROW(signer0->Verify(m, sig0));
}