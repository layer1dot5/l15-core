#include "frost_signer.hpp"

#include <algorithm>
#include <deque>
#include <concepts>
#include <atomic>

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

}

struct FrostStep : public std::enable_shared_from_this<FrostStep>
{
    std::weak_ptr<FrostSigner> mSigner;
    details::OperationMapId mOpId;
    std::atomic<uint16_t> m_status;

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

    explicit FrostStep(std::weak_ptr<FrostSigner>& signer, details::OperationMapId opid) : mSigner(signer), mOpId(move(opid)), m_status(0) {}
    virtual ~FrostStep() = default;

    virtual const char *Name() const noexcept = 0;

    FrostStatus Status() const
    {
        uint16_t cur_status = m_status;
        if (get_send_status(cur_status) == (uint16_t)FrostStatus::Ready) {
            return FrostStatus::Ready;
        }
        else {
            uint16_t combined = get_send_status(cur_status) | get_recv_status(cur_status);
            if (combined == (uint16_t)FrostStatus::Confirmed)
                return FrostStatus::Confirmed;
            else if ((combined ^ ((uint16_t)FrostStatus::Confirmed | (uint16_t)FrostStatus::Completed)) == 0)
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

    void DefaultSend(const xonly_pubkey&, p2p::frost_message_ptr);
    void DefaultPublish(p2p::frost_message_ptr);

    /// Returns true if message is arrived at a first time (no duplicate is found)
    bool DefaultReceive(p2p::frost_message_ptr);

    /// Return true if this step is in completed state after sending the message
    virtual bool MessageSend(const std::optional<const xonly_pubkey>&, p2p::frost_message_ptr) = 0;

    /// Return true if this step is in completed state after receiving the message
    virtual bool MessageReceive(p2p::frost_message_ptr) = 0;

    virtual std::shared_ptr<FrostStep> GetNextStep() = 0;

    virtual void Start() = 0;
};

void FrostStep::DefaultSend(const xonly_pubkey& peer_pk, p2p::frost_message_ptr msg)
{
    auto signer = mSigner.lock();
    if (signer) {
        auto &peer_cache = signer->m_peers_cache[peer_pk];
        msg->confirmed_sequence = 0;

        for (auto &m: FrostSigner::received_messages(peer_cache)) {
            m.confirmed = true;
            if (m.message->sequence > msg->confirmed_sequence) msg->confirmed_sequence = m.message->sequence;
        }

        signer->PeerService().Send(peer_pk, msg, []() {});

        auto pos = rgs::find_if(FrostSigner::sent_messages(peer_cache), [&msg](const auto &m) { return *(m.message) == *msg; });
        if (FrostSigner::sent_messages(peer_cache).end() == pos) {
            FrostSigner::sent_messages(peer_cache).push_back({msg, false});
        }
    }
}

void FrostStep::DefaultPublish(p2p::frost_message_ptr msg)
{
    auto signer = mSigner.lock();
    if (signer) {

        signer->PeerService().Publish(msg,
                    [signer](const xonly_pubkey &peer_pk, p2p::frost_message_ptr msg) {
                        auto &recv_cache = FrostSigner::received_messages(signer->m_peers_cache[peer_pk]);
                        msg->confirmed_sequence = 0;
                        for (auto &m: recv_cache) {
                            m.confirmed = true;
                            if (m.message->sequence > msg->confirmed_sequence)
                                msg->confirmed_sequence = m.message->sequence;
                        }},
                    [](const xonly_pubkey &peer_pk, p2p::frost_message_ptr msg) {});

        rgs::for_each(signer->m_peers_cache | vs::transform([](auto &pair) -> details::peer_messages & { return pair.second; }),
                    [msg](auto &peer_cache) {
                        auto pos = rgs::find_if(FrostSigner::sent_messages(peer_cache),
                                                  [&msg](const auto &m) { return *(m.message) == *msg; });
                        if (FrostSigner::sent_messages(peer_cache).end() == pos) {
                            FrostSigner::sent_messages(peer_cache).push_back({msg, false});
                        }});
    }
}

bool FrostStep::DefaultReceive(p2p::frost_message_ptr received_msg)
{
    auto signer = mSigner.lock();
    if (signer) {
        auto &peer_cache = signer->m_peers_cache[received_msg->pubkey];

//        for (auto &m: FrostSigner::sent_messages(peer_cache)) {
//            if (!(m.confirmed = (received_msg->confirmed_sequence >= m.message->sequence))) {
//                // Resend or drop
//                if (m.message->confirmed_sequence < received_msg->sequence)
//                    m.message->confirmed_sequence = received_msg->sequence;
//                signer->PeerService().Send(received_msg->pubkey, m.message, []() {/*TODO: drop on error?*/});
//            }
//        }

        auto pos = rgs::find_if(FrostSigner::received_messages(peer_cache),
                                [&received_msg](const auto &m) { return *(m.message) == *received_msg; });
        if (pos == FrostSigner::received_messages(peer_cache).end()) {

            signer->SignerApi()->Accept(*received_msg);
            FrostSigner::received_messages(peer_cache).push_back({received_msg, false});

            return true;
        }
    }
    // else it's a duplicate of some already accepted message
    return false;
}

//====================================================================================================================

struct ProcessSignatureNonces : public FrostStep
{
    explicit ProcessSignatureNonces(std::weak_ptr<FrostSigner>& s, details::OperationMapId opid) : FrostStep(s, opid) {}

    const char *Name() const noexcept override
    { return "ProcessSignatureNonces"; }

    bool MessageSend(const std::optional<const xonly_pubkey>&, p2p::frost_message_ptr msg) override
    {
        if (msg->id == p2p::FROST_MESSAGE::NONCE_COMMITMENTS) {
            DefaultPublish(msg);
            return true;
        }
        return false;
    }

    bool MessageReceive(p2p::frost_message_ptr msg) override
    {
        if (msg->id == p2p::FROST_MESSAGE::NONCE_COMMITMENTS) {
            DefaultReceive(msg);
            return true;
        }
        return false;
    }

    void Start() override
    {
        auto signer = mSigner.lock();
        if (signer) {
            //signer->SignerService().PublishNonces(mSigner.SignerApi(), 3);
        }
    }

    std::shared_ptr<FrostStep> GetNextStep() override
    { return nullptr; }

};


struct ProcessKeyCommitments : public FrostStep
{
    std::atomic_size_t commitments_received;
    std::shared_ptr<FrostStep> next_step;

    explicit ProcessKeyCommitments(std::weak_ptr<FrostSigner> s, details::OperationMapId opid) : FrostStep(s, opid), commitments_received(0), next_step(MakeNextStep()) {}

    const char *Name() const noexcept override
    { return "ProcessKeyCommitments"; }

    bool MessageSend(const std::optional<const xonly_pubkey>&, p2p::frost_message_ptr msg) override
    {
        if (msg->id == p2p::FROST_MESSAGE::KEY_COMMITMENT) {
            DefaultPublish(msg);
            SendStatus(FrostStatus::Completed);
            return true;
        }
        return false;
    }

    bool MessageReceive(p2p::frost_message_ptr msg) override
    {
        if (msg->id == p2p::FROST_MESSAGE::KEY_COMMITMENT) {
            auto signer = mSigner.lock();
            if (signer) {
                if (DefaultReceive(msg) && ++commitments_received >= (signer->N-1)) {
                    RecvStatus(FrostStatus::Completed);
                    return true;
                }
            }
        }
        return false;
    }

    void Start() override
    {
        auto signer = mSigner.lock();
        if (signer) {
            SendStatus(FrostStatus::InProgress);
            signer->SignerService().PublishKeyShareCommitment(signer->SignerApi(), [](){}, [ws=mSigner, opid = mOpId]() {
                auto signer = ws.lock();
                if (signer) {
                    try {
                        std::throw_with_nested(details::FrostOperationFailure(opid));
                    }
                    catch(...) {
                        signer->m_aggpk_promise.set_exception(std::current_exception());
                    }
                }
            });
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

    explicit ProcessKeyShares(std::weak_ptr<FrostSigner>& s, details::OperationMapId opid) : FrostStep(s, opid), keyshares_sent(0), keyshares_received(0) {}

    const char *Name() const noexcept override
    { return "AggregateKey"; }

    bool MessageSend(const std::optional<const xonly_pubkey>& peer_pk, p2p::frost_message_ptr msg) override
    {
        if (msg->id == p2p::FROST_MESSAGE::KEY_SHARE) {
            auto signer = mSigner.lock();
            if (signer) {
                DefaultSend(peer_pk.value(), msg);
                if (++keyshares_sent >= (signer->N-1)) {
                    SendStatus(FrostStatus::Completed);
                    return true;
                }
            }
        }
        return false;
    }

    bool MessageReceive(p2p::frost_message_ptr msg) override
    {
        if (msg->id == p2p::FROST_MESSAGE::KEY_SHARE) {
            auto signer = mSigner.lock();
            if (signer) {
                if (DefaultReceive(msg) && ++keyshares_received >= (signer->N-1)) {
                    RecvStatus(FrostStatus::Completed);
                    return true;
                }
            }
        }
        return false;
    }

    void Start() override
    {
        auto signer = mSigner.lock();
        if (signer) {
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
                        std::throw_with_nested(details::FrostOperationFailure(opid));
                    }
                    catch(...) {
                        signer->m_aggpk_promise.set_exception(std::current_exception());
                    }
                }
            });
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

    explicit ProcessSignatureCommitments(std::weak_ptr<FrostSigner>& s, details::OperationMapId opid) : FrostStep(s, opid), commitments_received(0), next_step(MakeNextStep()) {}

    const char *Name() const noexcept override
    { return "ProcessSignatureCommitments"; }

    bool MessageSend(const std::optional<const xonly_pubkey>&, p2p::frost_message_ptr msg) override
    {
        if (msg->id == p2p::FROST_MESSAGE::SIGNATURE_COMMITMENT) {
            DefaultPublish(msg);
            SendStatus(FrostStatus::Completed);
            return true;
        }
        return false;
    }

    bool MessageReceive(p2p::frost_message_ptr msg) override
    {
        if (msg->id == p2p::FROST_MESSAGE::SIGNATURE_COMMITMENT) {
            auto signer = mSigner.lock();
            if (signer) {
                if (DefaultReceive(msg) && ++commitments_received >= (signer->K-1)) {
                    RecvStatus(FrostStatus::Completed);
                    return true;
                }
            }
        }
        return false;
    }

    void Start() override
    {
        SendStatus(FrostStatus::InProgress);
        //mSigner.SignerService().Sign(mSigner.SignerApi(), ).
    }

    std::shared_ptr<FrostStep> GetNextStep() override
    { return nullptr; }
};


struct AggregateSignature : public FrostStep
{
    explicit AggregateSignature(std::weak_ptr<FrostSigner>& s, details::OperationMapId opid) : FrostStep(s, opid) {}

    const char *Name() const noexcept override
    { return "AggregateSignature"; }

    bool MessageSend(const std::optional<const xonly_pubkey>& peer_pk, p2p::frost_message_ptr msg) override
    {
        if (msg->id == p2p::FROST_MESSAGE::SIGNATURE_SHARE) {
            DefaultSend(peer_pk.value(), msg);
            return true;
        }
        return false;
    }

    bool MessageReceive(p2p::frost_message_ptr msg) override
    {
        if (msg->id == p2p::FROST_MESSAGE::SIGNATURE_SHARE) {
            return DefaultReceive(msg);
        }
        return false;
    }

    void Start() override
    {
        SendStatus(FrostStatus::InProgress);
        /*mSigner.SignerService().Sign(mSigner.SignerApi());*/
    }

    std::shared_ptr<FrostStep> GetNextStep() override
    { return nullptr; }
};


template <std::derived_from<FrostStep> START_STEP>
class FrostOperationImpl : public FrostOperation
{
    std::weak_ptr<FrostSigner> mSigner;

    std::deque<std::shared_ptr<FrostStep>> mSteps;
    std::mutex m_steps_mutex;

    template<typename CALLABLE, typename... ARGS>
    FrostStatus MessageProcImpl(CALLABLE action, ARGS &... args);

public:
    explicit FrostOperationImpl(std::shared_ptr<FrostSigner> s, details::OperationMapId opid): FrostOperation(), mSigner(s), mSteps()
    {
        mSteps.emplace_back(std::make_shared<START_STEP>(s, opid));
        while (auto step = mSteps.back()->GetNextStep()) {
            mSteps.emplace_back(move(step));
        }
        mSteps.front()->Start();
    }

    ~FrostOperationImpl() override = default;;

    FrostStatus HandleSend(const std::optional<const xonly_pubkey>& peer_pk, p2p::frost_message_ptr m) override
    { return MessageProcImpl(&FrostStep::MessageSend, peer_pk, m); }

    FrostStatus HandleReceive(p2p::frost_message_ptr m) override
    { return MessageProcImpl(&FrostStep::MessageReceive, m); }
};

//====================================================================================================================

std::shared_ptr<FrostStep> ProcessKeyCommitments::MakeNextStep()
{ return std::make_shared<ProcessKeyShares>(mSigner, mOpId); }

std::shared_ptr<FrostStep> ProcessSignatureCommitments::MakeNextStep()
{ return std::make_shared<AggregateSignature>(mSigner, mOpId); }

//====================================================================================================================


template<std::derived_from<FrostStep> START_STEP>
template <typename CALLABLE, typename... ARGS>
FrostStatus FrostOperationImpl<START_STEP>::MessageProcImpl(CALLABLE action, ARGS&... args)
{
    FrostStatus res = FrostStatus::InProgress;
    std::vector<std::shared_ptr<FrostStep>> check_steps;
    check_steps.reserve(mSteps.size());
    {
        for (auto step: mSteps) {
            //stepState->MessageIsSent(peer_pk, m);
            // or
            //stepState->MessageIsReceived(m);
            bool check_completed = (step.get()->*action)(args...);
            if (check_completed) {
                check_steps.emplace_back(move(step));
            }
            else if (step->IsConfirmed() && !step->GetNextStep()) {
                res = FrostStatus::Completed;
            }
        }
    }

    {   // use mutex to avoid race condition in starting of operation's steps
        std::lock_guard steps_lock(m_steps_mutex);
        auto completed_it = rgs::find_if(check_steps, [](auto& s)
        {
            return (s->IsCompleted() && s->GetNextStep() && s->GetNextStep()->Status() == FrostStatus::Ready);
        });
        if (completed_it != check_steps.end()) {
            (*completed_it)->GetNextStep()->Start();
        }
    }

    return res;
}

//====================================================================================================================


void FrostSigner::HandleSendToPeer(const xonly_pubkey &peer_pk, p2p::frost_message_ptr m)
{
    std::vector<details::OperationMapId> completed;
    {
        std::shared_lock oplock(m_op_mutex);

        std::for_each(mOperations.begin(), mOperations.end(), [&](auto &op) {
            if (op.second->HandleSend(std::make_optional<const xonly_pubkey>(peer_pk), m) == FrostStatus::Completed) {
                completed.reserve(mOperations.size());
                completed.push_back(op.first);
            }
        });
    }

    if (!completed.empty()) {
        std::unique_lock oplock(m_op_mutex);
        for(auto opid: completed) {
            mOperations.erase(opid);
        }
    }
}

void FrostSigner::HandlePublish(p2p::frost_message_ptr m)
{
    std::vector<details::OperationMapId> completed;
    {
        std::shared_lock oplock(m_op_mutex);

        std::for_each(mOperations.begin(), mOperations.end(), [&](auto &op) {
            if (op.second->HandleSend(std::make_optional<const xonly_pubkey>(), m) == FrostStatus::Completed) {
                completed.reserve(mOperations.size());
                completed.push_back(op.first);
            }
        });
    }

    if (!completed.empty()) {
        std::unique_lock oplock(m_op_mutex);
        for(auto opid: completed) {
            mOperations.erase(opid);
        }
    }
}

void FrostSigner::HandleError(Error &&e)
{
    std::cerr << e.what() << ": " << e.details() << std::endl;
}

void FrostSigner::HandleIncomingMessage(p2p::frost_message_ptr m)
{
    std::vector<details::OperationMapId> completed;
    {
        std::shared_lock oplock(m_op_mutex);

        std::for_each(mOperations.begin(), mOperations.end(), [&](auto &op) {
            if (op.second->HandleReceive(m) == FrostStatus::Completed) {
                completed.reserve(mOperations.size());
                completed.push_back(op.first);
            }
        });
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
    mSignerApi->SetErrorHandler([ws](Error&& e){
        auto signer = ws.lock();
        if (signer) {
            signer->HandleError(move(e));
        }

    });
    mSignerApi->SetPublisher([ws](p2p::frost_message_ptr m){
        auto signer = ws.lock();
        if (signer) {
            signer->HandlePublish(move(m));
        }
    });

    rgs::for_each(m_peers_cache | vs::transform([](auto& p)->const xonly_pubkey&{return p.first; }), [this, ws](const auto &peer){
        mSignerApi->AddPeer(xonly_pubkey(peer), [ws](const xonly_pubkey& peer_pk, p2p::frost_message_ptr m){
            auto signer = ws.lock();
            if (signer) {
                signer->HandleSendToPeer(peer_pk, move(m));
            }
        });
    });

    mPeerService->Connect(mSignerApi->GetLocalPubKey(), [ws](p2p::frost_message_ptr m) {
        auto signer = ws.lock();
        if (signer) {
            signer->HandleIncomingMessage(move(m));
        }
    });
}

void FrostSigner::AggregateKey()
{
    if (m_aggpk_future.wait_for(std::chrono::microseconds(0)) == std::future_status::ready) {
        throw WrongFrostState("conflicting aggpk");
    }

    std::unique_lock oplock(m_op_mutex);

    if(!mOperations.empty())
        throw WrongFrostState("concurent aggpk");

    details::OperationMapId opid {0, details::OperationType::key};

    mOperations.emplace(opid, std::make_unique<FrostOperationImpl<ProcessKeyCommitments>>(std::shared_ptr<FrostSigner>(this->shared_from_this()), opid));
}

std::shared_future<void> FrostSigner::CommitNonces(size_t count)
{
    return std::shared_future<void>();
}

std::shared_future<signature> FrostSigner::Sign(uint256 message, core::operation_id opid)
{
    return std::shared_future<signature>();
}

void FrostSigner::Verify(uint256 message, signature sig) const
{

}

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