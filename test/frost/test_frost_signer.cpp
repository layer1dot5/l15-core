
#include <memory>
#include <future>
#include <algorithm>
#include <ranges>

#include "smartinserter.hpp"


#define CATCH_CONFIG_MAIN
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
#include "zmq_service.hpp"

using namespace l15;
using namespace l15::core;
using namespace l15::p2p;
using namespace l15::service;
using namespace l15::signer_service;
using namespace l15::frost;

struct ThreeSignersTestWrapper {
    WalletApi wallet;
    ChannelKeys keypair0, keypair1, keypair2;
    std::shared_ptr<service::GenericService> service;
    std::shared_ptr<SignerService> signerService;
    std::shared_ptr<ZmqService> peer0, peer1, peer2;
    std::shared_ptr<FrostSigner> signer0, signer1, signer2;

    ThreeSignersTestWrapper()
        : keypair0(wallet.Secp256k1Context())
        , keypair1(wallet.Secp256k1Context())
        , keypair2(wallet.Secp256k1Context())
        , service(std::make_shared<service::GenericService>(10))
        , signerService(std::make_shared<SignerService>(service))
        , peer0(std::make_shared<ZmqService>(wallet.Secp256k1Context(), service))
        , peer1(std::make_shared<ZmqService>(wallet.Secp256k1Context(), service))
        , peer2(std::make_shared<ZmqService>(wallet.Secp256k1Context(), service))
        , signer0(make_shared<FrostSigner>(keypair0, std::vector<xonly_pubkey>{keypair0.GetLocalPubKey(), keypair1.GetLocalPubKey(), keypair2.GetLocalPubKey()}, signerService, peer0))
        , signer1(make_shared<FrostSigner>(keypair1, std::vector<xonly_pubkey>{keypair0.GetLocalPubKey(), keypair1.GetLocalPubKey(), keypair2.GetLocalPubKey()}, signerService, peer1))
        , signer2(make_shared<FrostSigner>(keypair2, std::vector<xonly_pubkey>{keypair0.GetLocalPubKey(), keypair1.GetLocalPubKey(), keypair2.GetLocalPubKey()}, signerService, peer2))
    {
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

    SECTION("KeyAgg") {
        CHECK_NOTHROW(signer0->AggregateKey());
        CHECK_NOTHROW(signer1->AggregateKey());
        CHECK_NOTHROW(signer2->AggregateKey());

        xonly_pubkey aggpk0, aggpk1, aggpk2;

        CHECK_NOTHROW(aggpk0 = signer0->GetAggregatedPubKey().get());
        CHECK_NOTHROW(aggpk1 = signer1->GetAggregatedPubKey().get());
        CHECK_NOTHROW(aggpk2 = signer2->GetAggregatedPubKey().get());

        CHECK(aggpk0.get_vector() == aggpk1.get_vector());
        CHECK(aggpk0.get_vector() == aggpk2.get_vector());
    }

    SECTION("PubNonce") {
        auto nonce_res0 = signer0->CommitNonces(1);
        auto nonce_res1 = signer1->CommitNonces(1);
        auto nonce_res2 = signer2->CommitNonces(1);

        CHECK_NOTHROW(nonce_res0.wait());
        CHECK_NOTHROW(nonce_res1.wait());
        CHECK_NOTHROW(nonce_res2.wait());
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::clog << "Sleep completed" << std::endl;

//    bytevector message_data32 {'T','h','i','s',' ','i','s',' ','t','e','s','t',' ','d','a','t','a',' ','t','o',' ','b','e',' ','s','i','g','n','e','d','!','!'};
//    REQUIRE(message_data32.size() == 32);
//
//    uint256 m(message_data32);
//
//    auto sign_res0 = signer0->Sign(m, 0);
//    auto sign_res1 = signer1->Sign(m, 0);
//
//    signature sig0, sig1;
//    CHECK_NOTHROW(sig0 = sign_res0.get());
//    CHECK_NOTHROW(sig1 = sign_res1.get());
//
//    std::cout << HexStr(sig0) << std::endl;
//
//    REQUIRE_FALSE(IsZeroArray(sig1));
//    CHECK((sig0 == sig1));
//
//    CHECK_NOTHROW(signer0->Verify(m, sig0));
}
