#include "frost_signer.hpp"

#include <algorithm>
#include <deque>
#include <concepts>
#include <atomic>
#include <list>

#include <tbb/concurrent_unordered_map.h>


namespace l15::frost {

namespace rgs = std::ranges;
namespace vs = std::views;

namespace {

uint16_t get_send_status(uint16_t full_status)
{ return full_status >> 8; }

uint16_t set_send_status(uint16_t status)
{ return status << 8; }

uint16_t get_recv_status(uint16_t full_status)
{ return full_status & 0x0ff; }

uint16_t set_recv_status(uint16_t status)
{ return status & 0x0ff; }

std::string translate(FrostStatus s) {
    switch (s) {
    case FrostStatus::Ready:
        return "Ready";
    case FrostStatus::InProgress:
        return "InProgress";
    case FrostStatus::Completed:
        return "Completed";
    case FrostStatus::Confirmed:
        return "Confirmed";
    case FrostStatus::Error:
        return "Error";
    }
}

details::message_queue& send_queue(details::peer_messages& cache)
{ return std::get<0>(cache); }

std::shared_mutex& send_mutex(details::peer_messages& cache)
{ return *std::get<1>(cache); }

details::message_queue& recv_queue(details::peer_messages& cache)
{ return std::get<2>(cache); }

std::shared_mutex& recv_mutex(details::peer_messages& cache)
{ return *std::get<3>(cache); }

void push_with_priority(details::message_queue& queue, p2p::frost_message_ptr m)
{
    auto it = std::find_if(queue.rbegin(), queue.rend(), [&](const auto &s) {
        return s.message->id <= m->id;
    });
    if (it == queue.rend() || it->message->id != m->id) {
        details::message_status s = {m, FrostStatus::Ready};
        queue.emplace(it.base(), move(s));
    }
    else {
        it->message = move(m);
    }

    queue.emplace_back(details::message_status{m, FrostStatus::Ready});
    std::sort(queue.begin(), queue.end());
}

}

struct FrostStep
{
    std::weak_ptr<FrostSigner> mSigner;
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

    explicit FrostStep(std::weak_ptr<FrostSigner>&& signer, details::OperationMapId opid) : mSigner(move(signer)), mOpId(move(opid)), m_status(0) {}
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

    void DefaultSend(FrostSigner& signer, const xonly_pubkey&, details::message_status&, uint16_t confirm_seq);
    //void DefaultPublish(p2p::FROST_MESSAGE id);

    /// Returns true if message is arrived at a first time (no duplicate is found)
    bool DefaultReceive(FrostSigner &signer, details::message_status &recv_status);

    /// return: true if the message passed as urgument is queued
    bool CheckAndQueueSendImpl(FrostSigner &signer, const std::optional<const xonly_pubkey> &, p2p::frost_message_ptr, p2p::FROST_MESSAGE);
    virtual bool CheckAndQueueSend(FrostSigner &signer, const std::optional<const xonly_pubkey> &, p2p::frost_message_ptr) = 0;

    /// Return true if this step is in completed state after sending the message
    virtual bool MessageSend(FrostSigner &signer, const std::optional<const xonly_pubkey> &) = 0;

    /// return: true if the message passed as urgument is queued
    bool CheckAndQueueReceiveImpl(FrostSigner &signer, p2p::frost_message_ptr, p2p::FROST_MESSAGE);
    virtual bool CheckAndQueueReceive(FrostSigner &signer, p2p::frost_message_ptr) = 0;

    /// Return true if this step is in completed state after receiving the message
    virtual bool MessageReceive(FrostSigner &signer, const xonly_pubkey &) = 0;

    virtual std::shared_ptr<FrostStep> GetNextStep() = 0;

    virtual void Start() = 0;
};

bool FrostStep::CheckAndQueueSendImpl(FrostSigner &signer, const std::optional<const xonly_pubkey> &peer_pk, p2p::frost_message_ptr m,
                                      p2p::FROST_MESSAGE frost_step)
{
    bool res;
    bool is_completed = (get_send_status(m_status) & (uint16_t)FrostStatus::Completed);
    if ((res = m->id == frost_step && !is_completed )) {
        if (peer_pk) {
            auto peer_it = signer.m_peers_cache.find(*peer_pk);
            if ((res = peer_it != signer.m_peers_cache.end())) {
                std::unique_lock lock(send_mutex(peer_it->second));
                push_with_priority(send_queue(peer_it->second), m);
            }
            else {
                throw p2p::WrongAddress(hex(*peer_pk));
            }
        }
        else {
            std::for_each(std::execution::par, signer.m_peers_cache.begin(), signer.m_peers_cache.end(), [m](auto& peer){
                std::unique_lock lock(send_mutex(peer.second));
                push_with_priority(send_queue(peer.second), m);
            });
        }
    }
    return res;
}

bool FrostStep::CheckAndQueueReceiveImpl(FrostSigner &signer, p2p::frost_message_ptr m, p2p::FROST_MESSAGE frost_step)
{
    bool res = false;
    if ((m->id == frost_step && !(get_recv_status(m_status) & (uint16_t) FrostStatus::Completed) )) {
        auto peer_it = signer.m_peers_cache.find(m->pubkey);
        if ((res = peer_it != signer.m_peers_cache.end())) {
            std::unique_lock lock(recv_mutex(peer_it->second));
            push_with_priority(recv_queue(peer_it->second), m);
        }
        else {
            throw p2p::WrongAddress(hex(m->pubkey));
        }

        // Check the step is already started (means start to send its messages)
        res = (get_send_status(m_status) & (uint16_t)FrostStatus::InProgress);
    }
    return res;
}

void FrostStep::DefaultSend(FrostSigner& signer, const xonly_pubkey& peer_pk, details::message_status& send_status, uint16_t confirm_seq)
{
    if (send_status.status != FrostStatus::Confirmed) { //Check the message status

        p2p::frost_message_ptr send_msg = send_status.message->Copy();

        send_msg->confirmed_sequence = confirm_seq;

        signer.PeerService().Send(peer_pk, send_msg, [s = mSigner](){
            if (auto signer = s.lock()) signer->HandleError();
        });

        send_status.status = FrostStatus::Completed;
    }
}

bool FrostStep::DefaultReceive(FrostSigner &signer, details::message_status &recv_status)
{
    if (recv_status.status == FrostStatus::Ready) {
        recv_status.status = FrostStatus::InProgress; //Really, excessive since the message processing happens under mutex lock
        signer.SignerService().Accept(signer.SignerApi(), recv_status.message);
        recv_status.status = FrostStatus::Completed;
        return true;
    }
    // else it's a duplicate of some already accepted message
    return false;
}

//====================================================================================================================

struct ProcessSignatureNonces : public FrostStep
{
    std::list<std::unique_ptr<std::promise<void>>> m_results;

    explicit ProcessSignatureNonces(std::weak_ptr<FrostSigner>&& s, details::OperationMapId opid) : FrostStep(move(s), opid) {
        assert(opid.optype == details::OperationType::nonce && !opid.opid);
    }

    const char *Name() const noexcept override
    { return "ProcessSignatureNonces"; }

    bool CheckAndQueueSend(FrostSigner &signer, const std::optional<const xonly_pubkey> &peer_pk, p2p::frost_message_ptr m) override
    {
        return FrostStep::CheckAndQueueSendImpl(signer, peer_pk, m, p2p::FROST_MESSAGE::NONCE_COMMITMENTS);
    }

    bool CheckAndQueueReceive(FrostSigner &signer, p2p::frost_message_ptr m) override
    { return FrostStep::CheckAndQueueReceiveImpl(signer, m, p2p::FROST_MESSAGE::NONCE_COMMITMENTS); }

    bool MessageSend(FrostSigner &signer, const std::optional<const xonly_pubkey> &peer_pk) override
    {
        if (peer_pk) throw std::runtime_error("ProcessSignatureNonces send with peer pubkey");

        for (auto &peer: signer.m_peers_cache) {
            uint16_t confirm_seq = 0;
            {   std::shared_lock recv_lock(recv_mutex(peer.second));
                if (!recv_queue(peer.second).empty()) {
                    confirm_seq = rgs::max(recv_queue(peer.second) | vs::transform([](auto &s) { return s.message->confirmed_sequence; }));
                }
            }

            std::unique_lock send_lock(send_mutex(peer.second));

            auto send_it = rgs::find_if(send_queue(peer.second), [](const auto& s){
                return s.message->id == p2p::FROST_MESSAGE::NONCE_COMMITMENTS && s.status == FrostStatus::Ready;
            });
            if (send_it != send_queue(peer.second).end()) {
                DefaultSend(signer, peer.first, *send_it, confirm_seq);
            }
        }

        return false;
    }

    bool MessageReceive(FrostSigner& signer, details::peer_messages& peer_cache)
    {
        std::unique_lock recv_lock(recv_mutex(peer_cache));

        auto recv_it = rgs::find_if(recv_queue(peer_cache), [](const auto& s){
            return s.message->id == p2p::FROST_MESSAGE::NONCE_COMMITMENTS && s.status == FrostStatus::Ready;
        });
        if (recv_it != recv_queue(peer_cache).end()) {
            DefaultReceive(signer, *recv_it);
        }
        return false;
    }

    bool MessageReceive(FrostSigner &signer, const xonly_pubkey &peer_pk) override
    { MessageReceive(signer, signer.m_peers_cache.at(peer_pk)); }

    std::future<void> Start(size_t count) {
        auto signer = mSigner.lock();
        if (signer) {
            auto res_it = m_results.emplace(m_results.end(), std::make_unique<std::promise<void>>());
            signer->SignerService().PublishNonces(signer->SignerApi(), count, [res_it, s=mSigner](){
                if(auto signer = s.lock()) (*res_it)->set_value();
            }, [res_it, s=mSigner](){
                if(auto signer = s.lock()) (*res_it)->set_exception(std::current_exception());
            });

            for (auto &peer_cache: signer->m_peers_cache | vs::values) {
                MessageReceive(*signer, peer_cache);
            }

            return (*res_it)->get_future();
        }
        else {
            throw std::runtime_error("Signer is destroyed");
        }
    }

    void Start() override
    { Start(1); }

    std::shared_ptr<FrostStep> GetNextStep() override
    { return nullptr; }
};


struct ProcessKeyCommitments : public FrostStep
{
    std::atomic_size_t commitments_received;
    std::shared_ptr<FrostStep> next_step;

    explicit ProcessKeyCommitments(std::weak_ptr<FrostSigner>&& s, details::OperationMapId opid) : FrostStep(move(s), opid), commitments_received(0), next_step(MakeNextStep()) {
        assert(opid.optype == details::OperationType::key && !opid.opid);
    }

    const char *Name() const noexcept override
    { return "ProcessKeyCommitments"; }

    bool CheckAndQueueSend(FrostSigner &signer, const std::optional<const xonly_pubkey> &peer_pk, p2p::frost_message_ptr m) override
    {
        return FrostStep::CheckAndQueueSendImpl(signer, peer_pk, m, p2p::FROST_MESSAGE::KEY_COMMITMENT);
    }

    bool CheckAndQueueReceive(FrostSigner &signer, p2p::frost_message_ptr m) override
    { return FrostStep::CheckAndQueueReceiveImpl(signer, m, p2p::FROST_MESSAGE::KEY_COMMITMENT); }

    bool MessageSend(FrostSigner &signer, const std::optional<const xonly_pubkey> &peer_pk) override
    {
        uint16_t status = SendStatus();
        if ((!(status & FrostStatus::InProgress)) || (status & FrostStatus::Completed))
            return false;

        if (peer_pk) throw std::runtime_error("ProcessKeyCommitments send with peer pubkey");

        for (auto &peer: signer.m_peers_cache) {
            uint16_t confirm_seq = 0;
            {   std::shared_lock recv_lock(recv_mutex(peer.second));
                if (!recv_queue(peer.second).empty())
                    confirm_seq = rgs::max(recv_queue(peer.second)|vs::transform([](auto& s){ return s.message->confirmed_sequence; }));
            }

            std::unique_lock send_lock(send_mutex(peer.second));

            auto send_it = rgs::find_if(send_queue(peer.second), [](const auto& s){
                return s.message->id == p2p::FROST_MESSAGE::KEY_COMMITMENT && s.status == FrostStatus::Ready;
            });
            if (send_it != send_queue(peer.second).end()) {
                DefaultSend(signer, peer.first, *send_it, confirm_seq);
            }
        }
        SendStatus(FrostStatus::Completed);
        return true;
    }

    bool MessageReceive(FrostSigner& signer, details::peer_messages& peer_cache)
    {
        std::unique_lock recv_lock(recv_mutex(peer_cache));
        auto recv_it = rgs::find_if(recv_queue(peer_cache), [](const auto& s){
            return s.message->id == p2p::FROST_MESSAGE::KEY_COMMITMENT && s.status == FrostStatus::Ready;
        });
        if (recv_it != recv_queue(peer_cache).end() && DefaultReceive(signer, *recv_it) && ++commitments_received >= (signer.N - 1)) {
            RecvStatus(FrostStatus::Completed);
            return true;
        }
        return false;
    }

    bool MessageReceive(FrostSigner &signer, const xonly_pubkey &peer_pk) override
    { return MessageReceive(signer, signer.m_peers_cache.at(peer_pk)); }

    void Start() override
    {
        if (auto signer = mSigner.lock()) {
            SendStatus(FrostStatus::InProgress);
            signer->SignerService().PublishKeyShareCommitment(signer->SignerApi(), [next_step = GetNextStep(), signerapi = signer->SignerApi()]() {
                std::clog << (std::ostringstream() << "KeyShareCommitment completed: " << hex(signerapi->GetLocalPubKey()).substr(0, 8)).str() << std::endl;
                next_step->Start();
            }, [ws = mSigner, opid = mOpId]() {
                auto signer = ws.lock();
                if (signer) {
                    try {
                        std::throw_with_nested(FrostOperationFailure(opid));
                    }
                    catch (...) {
                        signer->m_aggpk_promise.set_exception(std::current_exception());
                    }
                }
            });
            for (auto &peer_cache: signer->m_peers_cache | vs::values) {
                MessageReceive(*signer, peer_cache);
            }
        }
    }

    std::shared_ptr<FrostStep> MakeNextStep();

    std::shared_ptr<FrostStep> GetNextStep() override
    { return next_step; }
};


struct ProcessKeyShares : public FrostStep
{
    std::atomic_size_t keyshares_sent;
    std::atomic_size_t keyshares_received;

    explicit ProcessKeyShares(std::weak_ptr<FrostSigner>&& s, details::OperationMapId opid) : FrostStep(move(s), opid), keyshares_sent(0), keyshares_received(0) {}

    const char *Name() const noexcept override
    { return "ProcessKeyShares"; }

    bool CheckAndQueueSend(FrostSigner &signer, const std::optional<const xonly_pubkey> &peer_pk, p2p::frost_message_ptr m) override
    {
        //if (!peer_pk) throw std::runtime_error("ProcessKeyShares send without peer pubkey");
        return FrostStep::CheckAndQueueSendImpl(signer, peer_pk, m, p2p::FROST_MESSAGE::KEY_SHARE);
    }

    bool CheckAndQueueReceive(FrostSigner &signer, p2p::frost_message_ptr m) override
    { return FrostStep::CheckAndQueueReceiveImpl(signer, m, p2p::FROST_MESSAGE::KEY_SHARE); }

    bool MessageSend(FrostSigner &signer, const std::optional<const xonly_pubkey> &peer_pk) override
    {
        uint16_t status = SendStatus();
        if ((!(status & FrostStatus::InProgress)) || (status & FrostStatus::Completed))
            return false;

        if (!peer_pk) throw std::runtime_error("ProcessKeyShares send without peer pubkey");

        auto &peer = signer.m_peers_cache.at(*peer_pk);

        uint16_t confirm_seq = 0;
        {
            std::shared_lock recv_lock(recv_mutex(peer));
            if (!recv_queue(peer).empty()) {
                confirm_seq = rgs::max(recv_queue(peer) | vs::transform([](auto &s) { return s.message->confirmed_sequence; }));
            }
        }

        std::unique_lock send_lock(send_mutex(peer));

        auto send_it = rgs::find_if(send_queue(peer), [](const auto &s) {
            return s.message->id == p2p::FROST_MESSAGE::KEY_SHARE && s.status == FrostStatus::Ready;
        });
        if (send_it != send_queue(peer).end()) {
            DefaultSend(signer, *peer_pk, *send_it, confirm_seq);

            if (++keyshares_sent >= (signer.N - 1)) {
                SendStatus(FrostStatus::Completed);

                if (IsCompleted()) {
                    std::clog << (std::ostringstream() << "KeyAgg completed: " << hex(signer.SignerApi()->GetLocalPubKey()).substr(0, 8)).str() << std::endl;
                }

                return true;
            }
        }
        return false;
    }

    bool MessageReceive(FrostSigner& signer, details::peer_messages& peer_cache)
    {
        std::unique_lock recv_lock(recv_mutex(peer_cache));

        auto recv_it = rgs::find_if(recv_queue(peer_cache), [](const auto& s){
            return s.message->id == p2p::FROST_MESSAGE::KEY_SHARE && s.status == FrostStatus::Ready;
        });
        if (recv_it != recv_queue(peer_cache).end() && DefaultReceive(signer, *recv_it) && ++keyshares_received >= (signer.N - 1)) {
            RecvStatus(FrostStatus::Completed);

            if (IsCompleted()) {
                std::clog << (std::ostringstream() << "KeyAgg completed: " << hex(signer.SignerApi()->GetLocalPubKey()).substr(0, 8)).str() << std::endl;
            }

            return true;
        }
        return false;
    }

    bool MessageReceive(FrostSigner &signer, const xonly_pubkey &peer_pk) override
    { return MessageReceive(signer, signer.m_peers_cache.at(peer_pk)); }

    void Start() override
    {
        if (auto signer = mSigner.lock()) {
            clog << (std::ostringstream() << "ProcessKeyShares::Start() " << hex(signer->SignerApi()->GetLocalPubKey()).substr(0, 8) << ", " << std::this_thread::get_id).str() << std::endl;
            SendStatus(FrostStatus::InProgress);
            signer->SignerService().NegotiateKey(signer->SignerApi(),[ws = mSigner](const xonly_pubkey& aggpk){
                auto signer = ws.lock();
                if (signer) {
                    signer->m_aggpk_promise.set_value(signer->SignerApi()->GetAggregatedPubKey());
                }
            }, [ws=mSigner, opid=mOpId](){
                auto signer = ws.lock();
                if (signer) {
                    try {
                        std::throw_with_nested(FrostOperationFailure(opid));
                    }
                    catch(...) {
                        signer->m_aggpk_promise.set_exception(std::current_exception());
                    }
                }
            });
            for (auto &peer_cache: signer->m_peers_cache | vs::values) {
                MessageReceive(*signer, peer_cache);
            }
        }
    }

    std::shared_ptr<FrostStep> GetNextStep() override
    { return nullptr; }
};


struct ProcessSignatureCommitments : public FrostStep
{
    std::atomic_size_t commitments_received;
    std::shared_ptr<FrostStep> next_step;

    std::shared_ptr<FrostStep> MakeNextStep();

    explicit ProcessSignatureCommitments(std::weak_ptr<FrostSigner>&& s, details::OperationMapId opid, uint256 ) : FrostStep(move(s), opid), commitments_received(0), next_step(MakeNextStep()) {}

    const char *Name() const noexcept override
    { return "ProcessSignatureCommitments"; }

    bool CheckAndQueueSend(FrostSigner &signer, const std::optional<const xonly_pubkey> &peer_pk, p2p::frost_message_ptr m) override
    {
        return FrostStep::CheckAndQueueSendImpl(signer, peer_pk, m, p2p::FROST_MESSAGE::SIGNATURE_COMMITMENT);
    }

    bool CheckAndQueueReceive(FrostSigner &signer, p2p::frost_message_ptr m) override
    { return FrostStep::CheckAndQueueReceiveImpl(signer, m, p2p::FROST_MESSAGE::SIGNATURE_COMMITMENT); }

    bool MessageSend(FrostSigner& signer, const std::optional<const xonly_pubkey> &peer_pk) override
    {
        uint16_t status = SendStatus();
        if ((!(status & FrostStatus::InProgress)) || (status & FrostStatus::Completed))
            return false;

        if (peer_pk) throw std::runtime_error("ProcessSignatureCommitments send with peer pubkey");

        for (auto &peer: signer.m_peers_cache) {
            uint16_t confirm_seq;
            {   std::shared_lock recv_lock(recv_mutex(peer.second));
                confirm_seq = rgs::max(recv_queue(peer.second)|vs::transform([](auto& s){ return s.message->confirmed_sequence; }));
            }

            std::unique_lock send_lock(send_mutex(peer.second));

            auto send_it = rgs::find_if(send_queue(peer.second), [](const auto& s){
                return s.message->id == p2p::FROST_MESSAGE::SIGNATURE_COMMITMENT && s.status == FrostStatus::Ready;
            });
            if (send_it != send_queue(peer.second).end()) {
                DefaultSend(signer, peer.first, *send_it, confirm_seq);
            }
        }
        SendStatus(FrostStatus::Completed);
        return true;
    }

    bool MessageReceive(FrostSigner& signer, details::peer_messages& peer_cache)
    {
        std::unique_lock recv_lock(recv_mutex(peer_cache));

        auto recv_it = rgs::find_if(recv_queue(peer_cache), [](const auto& s){
            return s.message->id == p2p::FROST_MESSAGE::SIGNATURE_COMMITMENT && s.status == FrostStatus::Ready;
        });
        if (recv_it != recv_queue(peer_cache).end() && DefaultReceive(signer, *recv_it) && ++commitments_received >= (signer.K - 1)) {
            RecvStatus(FrostStatus::Completed);
            return true;
        }
        return false;
    }

    bool MessageReceive(FrostSigner &signer, const xonly_pubkey &peer_pk) override
    { return MessageReceive(signer, signer.m_peers_cache.at(peer_pk)); }

    void Start() override
    {
        if (auto signer = mSigner.lock()) {
            SendStatus(FrostStatus::InProgress);

            //signer->SignerService().Sign(signer->SignerApi(), ).

            for (auto &peer_cache: signer->m_peers_cache | vs::values) {
                MessageReceive(*signer, peer_cache);
            }
        }
    }

    std::shared_ptr<FrostStep> GetNextStep() override
    { return next_step; }
};


struct AggregateSignature : public FrostStep
{
    std::atomic_size_t sigshares_sent;
    std::atomic_size_t sigshares_received;

    explicit AggregateSignature(std::weak_ptr<FrostSigner>&& s, details::OperationMapId opid) : FrostStep(move(s), opid) {}

    const char *Name() const noexcept override
    { return "AggregateSignature"; }

    bool CheckAndQueueSend(FrostSigner &signer, const std::optional<const xonly_pubkey> &peer_pk, p2p::frost_message_ptr m) override
    {
        //if (!peer_pk) throw std::runtime_error("AggregateSignature send without peer pubkey");
        return FrostStep::CheckAndQueueSendImpl(signer, peer_pk, m, p2p::FROST_MESSAGE::SIGNATURE_SHARE);
    }

    bool CheckAndQueueReceive(FrostSigner &signer, p2p::frost_message_ptr m) override
    { return FrostStep::CheckAndQueueReceiveImpl(signer, m, p2p::FROST_MESSAGE::SIGNATURE_SHARE); }

    bool MessageSend(FrostSigner &signer, const std::optional<const xonly_pubkey> &peer_pk) override
    {
        uint16_t status = SendStatus();
        if ((!(status & FrostStatus::InProgress)) || (status & FrostStatus::Completed))
            return false;

        if (!peer_pk) throw std::runtime_error("AggregateSignature send without peer pubkey");

            auto &peer = signer.m_peers_cache.at(*peer_pk);

            uint16_t confirm_seq;
            {
                std::shared_lock recv_lock(recv_mutex(peer));
                confirm_seq = rgs::max(recv_queue(peer) | vs::transform([](auto &s) { return s.message->confirmed_sequence; }));
            }

            std::unique_lock send_lock(send_mutex(peer));

            auto send_it = rgs::find_if(send_queue(peer), [](const auto &s) {
                return s.message->id == p2p::FROST_MESSAGE::SIGNATURE_SHARE && s.status == FrostStatus::Ready;
            });
            if (send_it != send_queue(peer).end()) {
                DefaultSend(signer, *peer_pk, *send_it, confirm_seq);

                if (++sigshares_sent >= (signer.K - 1)) {
                    SendStatus(FrostStatus::Completed);
                    return true;
                }
            }
        return false;
    }

    bool MessageReceive(FrostSigner &signer, details::peer_messages& peer_cache)
    {
        std::unique_lock recv_lock(recv_mutex(peer_cache));

        auto recv_it = rgs::find_if(recv_queue(peer_cache), [](const auto& s){
            return s.message->id == p2p::FROST_MESSAGE::SIGNATURE_SHARE && s.status == FrostStatus::Ready;
        });
        if (recv_it != recv_queue(peer_cache).end() && DefaultReceive(signer, *recv_it) && ++sigshares_received >= (signer.K - 1)) {
            RecvStatus(FrostStatus::Completed);
            return true;
        }
        return false;
    }

    bool MessageReceive(FrostSigner &signer, const xonly_pubkey &peer_pk) override
    { return MessageReceive(signer, signer.m_peers_cache.at(peer_pk)); }

    void Start() override
    {
        if (auto signer = mSigner.lock()) {
            SendStatus(FrostStatus::InProgress);
            /*mSigner.SignerService().Sign(mSigner.SignerApi());*/
            for (auto &peer_cache: signer->m_peers_cache | vs::values) {
                MessageReceive(*signer, peer_cache);
            }
        }
    }

    std::shared_ptr<FrostStep> GetNextStep() override
    { return nullptr; }
};


class FrostOperation
{
    std::deque<std::shared_ptr<FrostStep>> mSteps;
    std::mutex m_steps_mutex;

    template<typename CALLABLE, typename... ARGS>
    bool MessageQueueImpl(CALLABLE action, ARGS&&... args);

    template<typename CALLABLE, typename... ARGS>
    FrostStatus MessageProcImpl(CALLABLE action, ARGS&&... args);

public:
    explicit FrostOperation(std::shared_ptr<FrostStep> startStep): mSteps()
    {
        mSteps.emplace_back(startStep);
        while (auto step = mSteps.back()->GetNextStep()) {
            mSteps.emplace_back(move(step));
        }
    }

    void Start()
    { mSteps.front()->Start(); }

    template <std::derived_from<FrostStep> STEP, typename RETURN, typename ... ARGS>
    std::future<RETURN> Start(ARGS&&... args)
    {
        try {
            //TODO: Looking for "clean" solution. This is only used for ProcessSignatureNonces
            FrostStep &s = *(mSteps.front());
            STEP &startStep = dynamic_cast<STEP &>(s);
            return startStep.Start(std::forward<ARGS>(args)...);
        }
        catch(...) {
            std::throw_with_nested(FrostOperationFailure(mSteps.front()->OperatonId()));
        }
    }

    bool
    CheckAndQueueSendingMessage(FrostSigner &signer, const std::optional<const xonly_pubkey> &peer_pk, p2p::frost_message_ptr m)
    { return MessageQueueImpl(&FrostStep::CheckAndQueueSend, signer, peer_pk, m); }

    FrostStatus HandleSend(FrostSigner& signer, const std::optional<const xonly_pubkey> &peer_pk)
    { return MessageProcImpl(&FrostStep::MessageSend, signer, peer_pk); }

    bool CheckAndQueueReceivedMessage(FrostSigner &signer, p2p::frost_message_ptr m)
    { return MessageQueueImpl(&FrostStep::CheckAndQueueReceive, signer, m); }

    FrostStatus HandleReceive(FrostSigner& signer, const xonly_pubkey &peer_pk)
    { return MessageProcImpl(&FrostStep::MessageReceive, signer, peer_pk); }
};

//====================================================================================================================

std::shared_ptr<FrostStep> ProcessKeyCommitments::MakeNextStep()
{ return std::make_shared<ProcessKeyShares>(std::weak_ptr<FrostSigner>(mSigner), mOpId); }

std::shared_ptr<FrostStep> ProcessSignatureCommitments::MakeNextStep()
{ return std::make_shared<AggregateSignature>(std::weak_ptr<FrostSigner>(mSigner), mOpId); }

//====================================================================================================================

template <typename CALLABLE, typename... ARGS>
bool FrostOperation::MessageQueueImpl(CALLABLE action, ARGS&&... args)
{
    for (auto& step: mSteps) {
        if ((step.get()->*action)(std::forward<ARGS>(args)...))
            return true;
    }
    return false;
}

template <typename CALLABLE, typename... ARGS>
FrostStatus FrostOperation::MessageProcImpl(CALLABLE action, ARGS&&... args)
{
    FrostStatus res = FrostStatus::InProgress;
    std::vector<std::shared_ptr<FrostStep>> check_steps;
    check_steps.reserve(mSteps.size());

    for (auto step: mSteps) {
        //stepState->MessageIsSent(peer_pk, m);
        // or
        //stepState->MessageIsReceived(m);
        bool check_completed = (step.get()->*action)(std::forward<ARGS>(args)...);
        /*if (check_completed) {
            check_steps.emplace_back(move(step));
        }
        else */if (step->IsConfirmed() && !step->GetNextStep()) {
            res = FrostStatus::Completed;
        }
    }

    // use mutex to avoid race condition in starting of operation's steps
//    {   std::lock_guard steps_lock(m_steps_mutex);
//
//        auto completed_it = rgs::find_if(check_steps, [](auto& s)
//        {
//            return (s->IsCompleted() && s->GetNextStep() && s->GetNextStep()->Status() == FrostStatus::Ready);
//        });
//        if (completed_it != check_steps.end()) {
//            (*completed_it)->GetNextStep()->Start();
//        }
//    }

    return res;
}

//====================================================================================================================

void FrostSigner::HandleError()
{
    print_error(std::cerr);
}


void FrostSigner::Send(const xonly_pubkey &peer_pk, p2p::frost_message_ptr m)
{
    auto opt_peer_pk =  std::make_optional<const xonly_pubkey>(peer_pk);
    std::vector<details::OperationMapId> completed;

    {   std::shared_lock oplock(m_op_mutex);

        for(auto& op : mOperations) {
            if (op.second->CheckAndQueueSendingMessage(*this, opt_peer_pk, m)) {
                if (op.second->HandleSend(*this, opt_peer_pk) == FrostStatus::Completed) {
                    completed.reserve(mOperations.size());
                    completed.push_back(op.first);
                }
                break;
            }
        }
    }

    if (!completed.empty()) {
        std::unique_lock oplock(m_op_mutex);
        for(auto opid: completed) {
            mOperations.erase(opid);
        }
    }
}

void FrostSigner::Publish(p2p::frost_message_ptr m)
{
    std::optional<const xonly_pubkey> empty_pk;
    std::vector<details::OperationMapId> completed;

    { std::shared_lock oplock(m_op_mutex);

        for(auto& op : mOperations) {
            if (op.second->CheckAndQueueSendingMessage(*this, empty_pk, m)) {
                if (op.second->HandleSend(*this, empty_pk) == FrostStatus::Completed) {
                    completed.reserve(mOperations.size());
                    completed.push_back(op.first);
                }
                break;
            }
        }
    }

    if (!completed.empty()) {
        std::unique_lock oplock(m_op_mutex);
        for(auto opid: completed) {
            mOperations.erase(opid);
        }
    }
}

void FrostSigner::Receive(p2p::frost_message_ptr m)
{
    std::vector<details::OperationMapId> completed;

    { std::shared_lock oplock(m_op_mutex);

        for(auto& op : mOperations) {
            if (op.second->CheckAndQueueReceivedMessage(*this, m)) {
                if (op.second->HandleReceive(*this, m->pubkey) == FrostStatus::Completed) {
                    completed.reserve(mOperations.size());
                    completed.push_back(op.first);
                }
            }
        }
    }

    if (!completed.empty()) {
        std::unique_lock oplock(m_op_mutex);
        for(auto opid: completed) {
            mOperations.erase(opid);
        }
    }
}

void FrostSigner::Start()
{
    auto ws = weak_from_this();
    mSignerApi->SetErrorHandler([ws](auto&& e){
        auto signer = ws.lock();
        if (signer) {
            signer->HandleError();
        }

    });
    mSignerApi->SetPublisher([ws](p2p::frost_message_ptr m){
        auto signer = ws.lock();
        if (signer) {
            signer->Publish(move(m));
        }
    });

    rgs::for_each(m_peers_cache | vs::transform([](auto& p)->const xonly_pubkey&{return p.first; }), [this, ws](const auto &peer){
        mSignerApi->AddPeer(xonly_pubkey(peer), [ws](const xonly_pubkey& peer_pk, p2p::frost_message_ptr m){
            auto signer = ws.lock();
            if (signer) {
                signer->Send(peer_pk, move(m));
            }
        });
    });

    mPeerService->Connect(mSignerApi->GetLocalPubKey(), [ws](p2p::frost_message_ptr m) {
        auto signer = ws.lock();
        if (signer) {
            signer->Receive(move(m));
        }
    });

    details::OperationMapId opid {0, details::OperationType::nonce};
    mOperations.emplace(opid, std::make_shared<FrostOperation>(std::make_shared<ProcessSignatureNonces>(shared_from_this(), opid)));
}

void FrostSigner::AggregateKey()
{
    if (m_aggpk_future.wait_for(std::chrono::microseconds(0)) == std::future_status::ready) {
        throw WrongFrostState("conflicting aggpk");
    }

    std::unique_lock oplock(m_op_mutex);

    if(mOperations.size() > 1)
        throw WrongFrostState("concurent aggpk??");

    details::OperationMapId opid {0, details::OperationType::key};
    auto opres = mOperations.emplace(opid, std::make_shared<FrostOperation>(std::make_shared<ProcessKeyCommitments>(this->shared_from_this(), opid)));
    opres.first->second->Start();
}

std::shared_future<void> FrostSigner::CommitNonces(size_t count)
{
    details::OperationMapId opid {0, details::OperationType::nonce};
    return mOperations[opid]->Start<ProcessSignatureNonces, void>(count);
}

std::shared_future<signature> FrostSigner::Sign(uint256 message, core::operation_id opid)
{
    return std::shared_future<signature>();
}

void FrostSigner::Verify(uint256 message, signature sig) const
{

}

FrostSigner::~FrostSigner() = default;

namespace details {

bool operator< (const OperationMapId& op1, const OperationMapId& op2) {
    if (op1.optype == OperationType::sign && op2.optype == OperationType::sign)
        return op1.opid < op2.opid;
    else
        return op1.optype < op2.optype;
}

std::string OperationMapId::describe() const
{
    switch (optype) {
    case OperationType::nonce:
        return "nonce";
    case OperationType::key:
        return "keyagg";
    case OperationType::sign:
        return (std::ostringstream() << "sign/" << opid).str();
    }
}

} // namespace details

}