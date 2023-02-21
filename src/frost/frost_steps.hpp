#pragma once

#include <concepts>

#include "frost_common.hpp"
#include "async_result.hpp"

namespace l15::frost {

namespace details {

typedef std::deque<details::message_status> message_queue;
typedef std::unique_ptr<std::shared_mutex> shared_mutex_ptr;
typedef std::tuple<message_queue, shared_mutex_ptr, message_queue, shared_mutex_ptr> peer_messages;
typedef std::unordered_map<xonly_pubkey, peer_messages, l15::hash<xonly_pubkey>> operation_cache;

}

class FrostOperationFailure: public Error
{
    const details::OperationMapId mFailOpId;
public:
    explicit FrostOperationFailure(details::OperationMapId op) noexcept
            : Error(op.describe()), mFailOpId(op) {}
    FrostOperationFailure(const FrostOperationFailure&) = default;
    FrostOperationFailure(FrostOperationFailure&&) = default;

    const char* what() const noexcept override
    { return "FrostOperationFailure"; }
};

class FrostSignerBase {
protected:
    friend class FrostStep;
    friend class NonceCommit;
    friend class KeyCommit;
    friend class KeyShare;
    friend class SigCommit;
    friend class SigAgg;

    const size_t N;
    const size_t K;

    std::shared_ptr<core::SignerApi> mSignerApi;
    std::shared_ptr<signer_service::SignerService> mSignerService;
    std::shared_ptr<p2p::P2PInterface<xonly_pubkey, p2p::FrostMessage>> mPeerService;

    details::operation_cache m_peers_cache;

    FrostSignerBase(core::ChannelKeys keypair, std::ranges::input_range auto&& peers,
                    std::shared_ptr<signer_service::SignerService> signerService,
                    std::shared_ptr<p2p::P2PInterface<xonly_pubkey, p2p::FrostMessage>> peerService)
            : N(std::ranges::size(peers)), K((N%2) ? (N+1)/2 : N/2)
            , mSignerApi(std::make_shared<core::SignerApi>(move(keypair), N, K)), mSignerService(move(signerService)), mPeerService(move(peerService))
            , m_peers_cache(N)
    {
        std::ranges::for_each(peers | std::views::filter([this](auto& p){ return p != mSignerApi->GetLocalPubKey(); }), [this](const auto &peer){
                    auto& p = m_peers_cache[peer]; // Initialize map with default elements per peer
                    std::get<1>(p) = std::make_unique<std::shared_mutex>();
                    std::get<3>(p) = std::make_unique<std::shared_mutex>();
                });
    }
    virtual ~FrostSignerBase() = default;

    signer_service::SignerService& SignerService()
    { return *mSignerService; }

    p2p::P2PInterface<xonly_pubkey, p2p::FrostMessage>& PeerService()
    { return *mPeerService; }

    std::shared_ptr<core::SignerApi> SignerApi()
    { return mSignerApi; }

    details::operation_cache& PeersCache()
    { return m_peers_cache; }

    virtual void HandleError() = 0;

};


struct FrostStep
{
    std::weak_ptr<FrostSignerBase> mSigner;
    details::OperationMapId mOpId;
    std::atomic<uint16_t> m_status;

    details::OperationMapId OperatonId() const
    { return mOpId; }

    uint16_t SendStatus() const { return get_send_status(m_status); }
    void SendStatus(FrostStatus status)
    {
        uint16_t cur_status;
        do {
            cur_status = m_status;
            if (get_send_status(cur_status) & (uint16_t)status) {
                throw WrongFrostState(translate(status) + " step send status is already set");
            }
        } while (!m_status.compare_exchange_strong(cur_status, cur_status | set_send_status((uint16_t) status), std::memory_order_relaxed));
    }
    uint16_t RecvStatus() const { return get_recv_status(m_status); }
    void RecvStatus(FrostStatus status)     {
        uint16_t cur_status;
        do {
            cur_status = m_status;
        } while (!m_status.compare_exchange_strong(cur_status, cur_status | set_recv_status((uint16_t) status), std::memory_order_relaxed));
    }

    explicit FrostStep(std::weak_ptr<FrostSignerBase>&& signer, details::OperationMapId opid) : mSigner(move(signer)), mOpId(move(opid)), m_status(0) {}
    virtual ~FrostStep() = default;

    virtual const char *Name() const noexcept = 0;

    FrostStatus Status() const
    {
        uint16_t cur_status = m_status;
        uint16_t send_status = get_send_status(cur_status);
        uint16_t recv_status = get_recv_status(cur_status);
        if (send_status == (uint16_t)FrostStatus::Ready) {
            return FrostStatus::Ready;
        }
        else {
            if ((send_status & (uint16_t)FrostStatus::Confirmed) && (recv_status & (uint16_t)FrostStatus::Confirmed))
                return FrostStatus::Confirmed;
            else if ((send_status & ((uint16_t)FrostStatus::Confirmed | (uint16_t)FrostStatus::Completed))
                     && (recv_status & ((uint16_t)FrostStatus::Confirmed | (uint16_t)FrostStatus::Completed)))
                return FrostStatus::Completed;
            else
                return FrostStatus::InProgress;
        }
    }
    bool IsCompleted() const
    {
        uint16_t cur_status = m_status;
        return (get_send_status(cur_status) & (uint16_t)FrostStatus::Completed) && (get_recv_status(cur_status) & (uint16_t)FrostStatus::Completed);
    }

    bool IsConfirmed() const
    {
        uint16_t cur_status = m_status;
        return (get_send_status(cur_status) & (uint16_t)FrostStatus::Confirmed) && (get_recv_status(cur_status) & (uint16_t)FrostStatus::Confirmed);
    }

    void DefaultSend(FrostSignerBase& signer, const xonly_pubkey&, details::message_status&, uint16_t confirm_seq) const;
    //void DefaultPublish(p2p::FROST_MESSAGE id);

    /// Returns true if message is arrived at a first time (no duplicate is found)
    bool DefaultReceive(FrostSignerBase& signer, details::message_status &recv_status) const;

    /// return: true if the message passed as urgument is queued
    bool CheckAndQueueSendImpl(FrostSignerBase& signer, const std::optional<const xonly_pubkey> &, p2p::frost_message_ptr, p2p::FROST_MESSAGE);
    virtual bool CheckAndQueueSend(FrostSignerBase &signer, const std::optional<const xonly_pubkey> &, p2p::frost_message_ptr) = 0;

    /// Return true if this step is in completed state after sending the message
    virtual bool MessageSend(FrostSignerBase& signer, const std::optional<const xonly_pubkey> &) = 0;

    /// return: true if the message passed as urgument is queued
    bool CheckAndQueueReceiveImpl(FrostSignerBase& signer, p2p::frost_message_ptr, p2p::FROST_MESSAGE);
    virtual bool CheckAndQueueReceive(FrostSignerBase &signer, p2p::frost_message_ptr) = 0;

    /// Return true if this step is in completed state after receiving the message
    virtual bool MessageReceive(FrostSignerBase &signer, const xonly_pubkey &) = 0;

    virtual std::shared_ptr<FrostStep> GetNextStep() = 0;
};



struct NonceCommit : public FrostStep
{
    explicit NonceCommit(std::weak_ptr<FrostSignerBase>&& s, details::OperationMapId opid) : FrostStep(move(s), opid) {
        assert(opid.optype == details::OperationType::nonce && !opid.opid);
    }

    const char *Name() const noexcept override
    { return "NonceCommit"; }

    bool CheckAndQueueSend(FrostSignerBase& signer, const std::optional<const xonly_pubkey> &peer_pk, p2p::frost_message_ptr m) override
    { return FrostStep::CheckAndQueueSendImpl(signer, peer_pk, m, p2p::FROST_MESSAGE::NONCE_COMMITMENTS); }

    bool CheckAndQueueReceive(FrostSignerBase& signer, p2p::frost_message_ptr m) override
    { return FrostStep::CheckAndQueueReceiveImpl(signer, m, p2p::FROST_MESSAGE::NONCE_COMMITMENTS); }

    bool MessageSend(FrostSignerBase& signer, const std::optional<const xonly_pubkey> &peer_pk) override;

    bool MessageReceive(FrostSignerBase& signer, details::peer_messages& peer_cache);

    bool MessageReceive(FrostSignerBase& signer, const xonly_pubkey &peer_pk) override
    { return MessageReceive(signer, signer.PeersCache().at(peer_pk)); }

    template<std::derived_from<cex::async_result_base<void>> RES>
    void Start(RES&& op_handler, size_t count) {
        auto signer = mSigner.lock();
        if (signer) {
            signer->SignerService().CommitSigNonces(signer->SignerApi(), count, std::forward<RES>(op_handler));

            for (auto &peer_cache: signer->PeersCache() | std::views::values) {
                MessageReceive(*signer, peer_cache);
            }
        }
//        else {
//            throw std::runtime_error("Signer is destroyed");
//        }
    }

    std::shared_ptr<FrostStep> GetNextStep() override
    { return nullptr; }
};


struct KeyShare : public FrostStep
{
    std::atomic_size_t keyshares_sent;
    std::atomic_size_t keyshares_received;

    explicit KeyShare(std::weak_ptr<FrostSignerBase>&& s, details::OperationMapId opid) : FrostStep(move(s), opid), keyshares_sent(0), keyshares_received(0) {}

    const char *Name() const noexcept override
    { return "KeyShare"; }

    bool CheckAndQueueSend(FrostSignerBase& signer, const std::optional<const xonly_pubkey> &peer_pk, p2p::frost_message_ptr m) override
    { return FrostStep::CheckAndQueueSendImpl(signer, peer_pk, m, p2p::FROST_MESSAGE::KEY_SHARE); }

    bool CheckAndQueueReceive(FrostSignerBase& signer, p2p::frost_message_ptr m) override
    { return FrostStep::CheckAndQueueReceiveImpl(signer, m, p2p::FROST_MESSAGE::KEY_SHARE); }

    bool MessageSend(FrostSignerBase& signer, const std::optional<const xonly_pubkey> &peer_pk) override;

    bool MessageReceive(FrostSignerBase& signer, details::peer_messages& peer_cache);

    bool MessageReceive(FrostSignerBase& signer, const xonly_pubkey &peer_pk) override
    { return MessageReceive(signer, signer.PeersCache().at(peer_pk)); }

    template<std::derived_from<cex::async_result_base<const xonly_pubkey&>> RES>
    void Start(RES&& op_handler)
    {
        if (auto signer = mSigner.lock()) {
            //clog << (std::ostringstream() << Name() << "::Start() " << hex(signer->SignerApi()->GetLocalPubKey()).substr(0, 8) << ", " << std::this_thread::get_id).str() << std::endl;
            SendStatus(FrostStatus::InProgress);

            signer->SignerService().NegotiateKey(signer->SignerApi(),
                cex::make_async_result<const xonly_pubkey&>([ws = mSigner](const xonly_pubkey& aggpk, RES&& op_handler){
                    auto signer = ws.lock();
                    if (signer) {
                        std::clog << (std::ostringstream() << "KeyShare API completed: " << hex(signer->SignerApi()->GetLocalPubKey()).substr(0, 8)).str() << std::endl;
                        op_handler(aggpk);
                    }
                }, [](RES&& op_handler){
                    op_handler.on_error();
                }, std::forward<RES>(op_handler)));

            for (auto &peer_cache: signer->PeersCache() | std::views::values) {
                MessageReceive(*signer, peer_cache);
            }
        }
    }

    std::shared_ptr<FrostStep> GetNextStep() override
    { return nullptr; }
};

struct KeyCommit : public FrostStep
{
    std::atomic_size_t commitments_received;
    std::shared_ptr<KeyShare> next_step;

    explicit KeyCommit(std::weak_ptr<FrostSignerBase>&& s, details::OperationMapId opid)
            : FrostStep(move(s), opid), commitments_received(0), next_step(MakeNextStep())
    {
        assert(opid.optype == details::OperationType::key && !opid.opid);
    }

    const char *Name() const noexcept override
    { return "KeyCommit"; }

    bool CheckAndQueueSend(FrostSignerBase& signer, const std::optional<const xonly_pubkey> &peer_pk, p2p::frost_message_ptr m) override
    { return FrostStep::CheckAndQueueSendImpl(signer, peer_pk, m, p2p::FROST_MESSAGE::KEY_COMMITMENT); }

    bool CheckAndQueueReceive(FrostSignerBase& signer, p2p::frost_message_ptr m) override
    { return FrostStep::CheckAndQueueReceiveImpl(signer, m, p2p::FROST_MESSAGE::KEY_COMMITMENT); }

    bool MessageSend(FrostSignerBase& signer, const std::optional<const xonly_pubkey> &peer_pk) override;

    bool MessageReceive(FrostSignerBase& signer, details::peer_messages& peer_cache);

    bool MessageReceive(FrostSignerBase& signer, const xonly_pubkey &peer_pk) override
    { return MessageReceive(signer, signer.PeersCache().at(peer_pk)); }

    template<std::derived_from<cex::async_result_base<const xonly_pubkey&>> RES>
    void Start(RES&& op_handler)
    {
        if (auto signer = mSigner.lock()) {
            SendStatus(FrostStatus::InProgress);
            signer->SignerService().ProcessKeyShareCommitment(signer->SignerApi(),
                cex::make_async_result<void>([next_step = next_step, signerapi = signer->SignerApi()](RES&& op_handler) mutable {
                    std::clog << (std::ostringstream() << "KeyCommit completed: " << hex(signerapi->GetLocalPubKey()).substr(0, 8)).str() << std::endl;
                    next_step->Start(std::forward<RES>(op_handler));
                }, [](RES&& op_handler) mutable {
                    op_handler.on_error();
                }, std::forward<RES>(op_handler)));
            for (auto &peer_cache: signer->PeersCache() | std::views::values) {
                MessageReceive(*signer, peer_cache);
            }
        }
    }

    std::shared_ptr<KeyShare> MakeNextStep()
    { return std::make_shared<KeyShare>(std::weak_ptr<FrostSignerBase>(mSigner), mOpId); }


    std::shared_ptr<FrostStep> GetNextStep() override
    { return next_step; }
};


struct SigAgg : public FrostStep, std::enable_shared_from_this<SigAgg>
{
    std::atomic_size_t sigshares_sent;
    std::atomic_size_t sigshares_received;

    explicit SigAgg(std::weak_ptr<FrostSignerBase> s, details::OperationMapId opid)
            : FrostStep(move(s), opid)
            , sigshares_sent(0)
            , sigshares_received(0)
    {}

    const char *Name() const noexcept override
    { return "SigAgg"; }

    bool CheckAndQueueSend(FrostSignerBase& signer, const std::optional<const xonly_pubkey> &peer_pk, p2p::frost_message_ptr m) override
    { return FrostStep::CheckAndQueueSendImpl(signer, peer_pk, m, p2p::FROST_MESSAGE::SIGNATURE_SHARE); }

    bool CheckAndQueueReceive(FrostSignerBase& signer, p2p::frost_message_ptr m) override
    { return FrostStep::CheckAndQueueReceiveImpl(signer, m, p2p::FROST_MESSAGE::SIGNATURE_SHARE); }

    bool MessageSend(FrostSignerBase& signer, const std::optional<const xonly_pubkey> &peer_pk) override;

    bool MessageReceive(FrostSignerBase& signer, details::peer_messages& peer_cache);

    bool MessageReceive(FrostSignerBase& signer, const xonly_pubkey &peer_pk) override
    { return MessageReceive(signer, signer.PeersCache().at(peer_pk)); }

    template<std::derived_from<cex::async_result_base<signature>> RES>
    void Start(RES&& op_handler)
    {
        if (auto signer = mSigner.lock()) {
            clog << (std::ostringstream() << Name() << "::Start() " << hex(signer->SignerApi()->GetLocalPubKey()).substr(0, 8) << ", " << std::this_thread::get_id).str() << std::endl;
            SendStatus(FrostStatus::InProgress);

            signer->SignerService().Sign(signer->SignerApi(), OperatonId().opid, std::forward<RES>(op_handler));

            for (auto &peer_cache: signer->PeersCache() | std::views::values) {
                MessageReceive(*signer, peer_cache);
            }
        }
    }

    std::shared_ptr<FrostStep> GetNextStep() override
    { return nullptr; }
};

struct SigCommit : public FrostStep
{
    std::atomic_size_t commitments_received;
    std::shared_ptr<SigAgg> next_step;
    uint256 message;

    std::shared_ptr<SigAgg> MakeNextStep()
    { return std::make_shared<SigAgg>(mSigner, mOpId); }

    explicit SigCommit(std::weak_ptr<FrostSignerBase>&& s, details::OperationMapId opid, uint256 m)
            : FrostStep(move(s), opid), commitments_received(0), next_step(MakeNextStep()), message(m)
    {
        assert(opid.optype == details::OperationType::sign && opid.opid > 0);
    }

    const char *Name() const noexcept override
    { return "SigCommit"; }

    bool CheckAndQueueSend(FrostSignerBase& signer, const std::optional<const xonly_pubkey> &peer_pk, p2p::frost_message_ptr m) override
    { return FrostStep::CheckAndQueueSendImpl(signer, peer_pk, m, p2p::FROST_MESSAGE::SIGNATURE_COMMITMENT); }

    bool CheckAndQueueReceive(FrostSignerBase& signer, p2p::frost_message_ptr m) override
    { return FrostStep::CheckAndQueueReceiveImpl(signer, m, p2p::FROST_MESSAGE::SIGNATURE_COMMITMENT); }

    bool MessageSend(FrostSignerBase& signer, const std::optional<const xonly_pubkey> &peer_pk) override;

    bool MessageReceive(FrostSignerBase& signer, details::peer_messages& peer_cache);

    bool MessageReceive(FrostSignerBase& signer, const xonly_pubkey &peer_pk) override
    { return MessageReceive(signer, signer.PeersCache().at(peer_pk)); }

    template<std::derived_from<cex::async_result_base<signature>> RES>
    void Start(RES&& op_handler) {
        if (auto signer = mSigner.lock()) {
            SendStatus(FrostStatus::InProgress);

            signer->SignerService().ProcessSignatureCommitments(signer->SignerApi(), message, OperatonId().opid, true,
                cex::make_async_result<void>([next_step=next_step, signerapi=signer->SignerApi()](RES&& op_handler) mutable {
                    std::clog << (std::ostringstream() << "SigCommit completed: " << hex(signerapi->GetLocalPubKey()).substr(0, 8)).str() << std::endl;
                    next_step->Start(std::forward<RES>(op_handler));
                }, [](RES&& op_handler){
                    op_handler.on_error();
                }, std::forward<RES>(op_handler)));

            for (auto &peer_cache: signer->PeersCache() | std::views::values) {
                MessageReceive(*signer, peer_cache);
            }
        }
    }

    std::shared_ptr<FrostStep> GetNextStep() override
    { return next_step; }
};


}
