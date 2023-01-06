#pragma once

#include <memory>
#include <ranges>
#include <future>
#include <map>

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

struct FrostOperation
{
    FrostOperation() = default;
    virtual ~FrostOperation() = default;
    virtual FrostStatus HandleSend(const std::optional<const xonly_pubkey>&, p2p::frost_message_ptr) { throw std::runtime_error(""); };
    virtual FrostStatus HandleReceive(p2p::frost_message_ptr) { throw std::runtime_error(""); };

};

class FrostSignerInterface// : public std::enable_shared_from_this<FrostSignerInterface>
{
public:
    virtual ~FrostSignerInterface() = default;
    virtual void HandleSendToPeer(const xonly_pubkey& peer_pk, p2p::frost_message_ptr m) = 0;
    virtual void HandlePublish(p2p::frost_message_ptr m) = 0;
    virtual void HandleError(Error&& e) = 0;
    virtual void HandleIncomingMessage(p2p::frost_message_ptr m) = 0;
};

struct message_status {
    p2p::frost_message_ptr message;
    bool confirmed;
};
typedef std::tuple<tbb::concurrent_vector<message_status>, tbb::concurrent_vector<message_status>> peer_messages;
typedef tbb::concurrent_unordered_map<xonly_pubkey, peer_messages, l15::hash<xonly_pubkey>> operation_cache;

enum class OperationType: uint16_t {nonce, key, sign};

struct OperationMapId {
    core::operation_id opid;
    OperationType optype;
};

bool operator< (const OperationMapId& op1, const OperationMapId& op2);

}


class FrostSigner : public details::FrostSignerInterface {

    friend class FrostState;
    friend class ProcessKeyCommitments;
    friend class ProcessKeyShares;
    friend class ProcessSignatureCommitments;

    const size_t N;
    const size_t K;

    std::shared_ptr<core::SignerApi> mSignerApi;
    std::shared_ptr<signer_service::SignerService> mSignerService;
    std::shared_ptr<p2p::P2PInterface<xonly_pubkey, p2p::FrostMessage>> mPeerService;

    details::operation_cache m_peers_cache;

    std::promise<const xonly_pubkey&> m_aggpk_promise;
    mutable std::future<const xonly_pubkey&> m_aggpk_future;

    std::promise<void> m_nonces_promise;
    mutable std::future<void> m_nonces_future;

    std::map<details::OperationMapId, std::unique_ptr<details::FrostOperation>> mOperations;
    std::shared_mutex m_op_mutex;

private:
    signer_service::SignerService& SignerService()
    { return *mSignerService; }

    p2p::P2PInterface<xonly_pubkey, p2p::FrostMessage>& PeerService()
    { return *mPeerService; }

    std::shared_ptr<core::SignerApi> SignerApi()
    { return mSignerApi; }

    tbb::concurrent_vector<details::message_status>& sent_messages(details::peer_messages& cache)
    { return std::get<0>(cache); }

    tbb::concurrent_vector<details::message_status>& received_messages(details::peer_messages& cache)
    { return std::get<1>(cache); }

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
            : N(std::ranges::size(peers)), K((N%2) ? (N+1)/2 : N/2)
            , mSignerApi(), mSignerService(move(signerService)), mPeerService(move(peerService))
            , m_peers_cache(N), m_aggpk_promise(), m_aggpk_future(m_aggpk_promise.get_future())
    {
        mSignerApi = std::make_shared<core::SignerApi>(move(keypair), N, K);

        mSignerApi->SetErrorHandler([this](Error&& e){ HandleError(move(e)); });
        mSignerApi->SetPublisher([this](p2p::frost_message_ptr m){ HandlePublish(move(m));});

        std::ranges::for_each(peers, [this](const auto &peer){
            mSignerApi->AddPeer(xonly_pubkey(peer), [this](const xonly_pubkey& peer_pk, p2p::frost_message_ptr m){
                HandleSendToPeer(peer_pk, move(m));
            });
            m_peers_cache[peer]; // Initialize map with default elements per peer
        });

        mPeerService->Subscribe(mSignerApi->GetLocalPubKey(), [this](p2p::frost_message_ptr m){
            HandleIncomingMessage(move(m));
        });

        AggregateKey();
    }

    ~FrostSigner() override = default;

    std::shared_future<const xonly_pubkey&> GetAggregatedPubKey() const
    { return m_aggpk_future.share(); }

    std::shared_future<const xonly_pubkey&> AggregateKey();

    std::shared_future<void> CommitNonces(size_t count);

    std::shared_future<signature> Sign(uint256 message, core::operation_id opid);

    void Verify(uint256 message, signature sig) const;
};

}