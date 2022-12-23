#pragma once

#include <memory>
#include <ranges>
#include <future>

#include <boost/container/flat_map.hpp>

#include "common.hpp"
#include "common_error.hpp"
#include "uint256.h"
#include "channel_keys.hpp"
#include "signer_api.hpp"
#include "signer_service.hpp"



namespace l15::frost {

// FrostSigner API is currently WIP prototype.
// The main focus is at internal state machine so far.

class WrongFrostState: public Error {
public:
    explicit WrongFrostState(std::string&& details) noexcept : Error(move(details)) {}
    const char* what() const noexcept override { return "WrongFrostState"; }
};


namespace details {

class FrostSignerInterface;

enum class FrostStatus {
    InProgress, Completed, Confirmed
};

struct FrostSM
{
    std::weak_ptr<FrostSignerInterface> mSigner;

    explicit FrostSM(std::weak_ptr<FrostSignerInterface> &&signer) : mSigner(move(signer)) {}
    virtual ~FrostSM() = default;
    virtual FrostStatus MessageIsSent(const std::optional<const xonly_pubkey>&, p2p::frost_message_ptr) = 0;
    virtual FrostStatus MessageIsReceived(p2p::frost_message_ptr) = 0;

};

class FrostSignerInterface : public std::enable_shared_from_this<FrostSignerInterface>
{
public:
    virtual ~FrostSignerInterface() = default;
    virtual void HandleSendToPeer(const xonly_pubkey& peer_pk, p2p::frost_message_ptr m) = 0;
    virtual void HandlePublish(p2p::frost_message_ptr m) = 0;
    virtual void HandleError(Error&& e) = 0;
    virtual void HandleIncomingMessage(p2p::frost_message_ptr m) = 0;
};

}

class FrostSigner : public details::FrostSignerInterface {

    friend class details::FrostSM;

    //boost::container::flat_map<xonly_pubkey, std::string, l15::less<xonly_pubkey>> m_peers_config;
    std::shared_ptr<core::SignerApi> mSignerApi;
    std::shared_ptr<signer_service::SignerService> mSignerService;
    std::shared_ptr<p2p::P2PInterface<xonly_pubkey, p2p::FrostMessage>> mPeerService;

    std::promise<const xonly_pubkey&> m_aggpk_promise;
    mutable std::future<const xonly_pubkey&> m_aggpk_future;

    boost::container::flat_map<core::operation_id, std::unique_ptr<details::FrostSM>> mOperations;
    std::shared_mutex m_op_mutex;
    //std::unique_ptr<details::FrostSM> mState;

private:
    void HandleSendToPeer(const xonly_pubkey& peer_pk, p2p::frost_message_ptr m) override;
    void HandlePublish(p2p::frost_message_ptr m) override;
    void HandleError(Error&& e) override;

    void HandleIncomingMessage(p2p::frost_message_ptr m) override;


    //void MakeSignature(const xonly_pubkey& , const uint256& );
public:

    explicit FrostSigner(
            core::ChannelKeys keypair, std::ranges::input_range auto&& peers,
            std::shared_ptr<signer_service::SignerService> signerService,
            std::shared_ptr<p2p::P2PInterface<xonly_pubkey, p2p::FrostMessage>> peerService)
            : mSignerApi(), mSignerService(move(signerService)), mPeerService(move(peerService))
            , m_aggpk_promise(), m_aggpk_future(m_aggpk_promise.get_future())
    {
        size_t N =  std::ranges::size(peers);
        size_t K = (N%2) ? (N+1)/2 : N/2;

        mSignerApi = std::make_shared<core::SignerApi>(move(keypair), N, K);

        mSignerApi->SetErrorHandler([this](Error&& e){ HandleError(move(e)); });
        mSignerApi->SetPublisher([this](p2p::frost_message_ptr m){ HandlePublish(move(m));});

        std::ranges::for_each(peers, [this](const auto &peer){
            mSignerApi->AddPeer(xonly_pubkey(peer.first), [this](const xonly_pubkey& peer_pk, p2p::frost_message_ptr m){
                HandleSendToPeer(peer_pk, move(m)); });
        });

        mPeerService->Subscribe(mSignerApi->GetLocalPubKey(), [this](p2p::frost_message_ptr m){
            HandleIncomingMessage(move(m));
        });

        //StartKeyAgg();
    }

    ~FrostSigner() override = default;

    std::shared_future<const xonly_pubkey&> GetAggregatedPubKey() const
    { return m_aggpk_future.share(); }

    void StartKeyAgg();
};

}