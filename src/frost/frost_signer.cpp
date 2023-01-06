#include "frost_signer.hpp"

#include <algorithm>
#include <deque>
#include <concepts>
#include <atomic>

#include <tbb/concurrent_unordered_map.h>

#include "p2p_frost.hpp"

namespace l15::frost {

namespace rgs = std::ranges;
namespace vs = std::views;

struct FrostState
{
    FrostSigner& mSigner;
    details::FrostStatus send_status;
    details::FrostStatus recv_status;

    explicit FrostState(FrostSigner& signer) : mSigner(signer)
        , send_status(details::FrostStatus::InProgress)
        , recv_status(details::FrostStatus::InProgress)
    {}

    virtual ~FrostState() = default;

    virtual const char *Name() const noexcept = 0;

    bool IsCompleted() const
    { return (send_status == details::FrostStatus::Completed) && (recv_status == details::FrostStatus::Completed); }

    bool IsConfirmed() const
    { return (send_status == details::FrostStatus::Confirmed) && (recv_status == details::FrostStatus::Confirmed); }

    void DefaultSend(const xonly_pubkey&, p2p::frost_message_ptr);
    void DefaultPublish(p2p::frost_message_ptr);

    /// Returns true if message is arrived at a first time (no duplicate is found)
    bool DefaultReceive(p2p::frost_message_ptr);

    /// Return true if this step is intended to process the message
    virtual bool MessageSend(const std::optional<const xonly_pubkey>&, p2p::frost_message_ptr) = 0;

    /// Return true if this step is intended to process the message
    virtual bool MessageReceive(p2p::frost_message_ptr) = 0;

    virtual std::unique_ptr<FrostState> GetNextState() const = 0;
};

void FrostState::DefaultSend(const xonly_pubkey& pk, p2p::frost_message_ptr msg)
{
    auto &peer_cache = mSigner.m_peers_cache[pk];
    auto confirm_id = p2p::FROST_MESSAGE::NO_VALUE;

    rgs::for_each(mSigner.received_messages(peer_cache), [&confirm_id](auto &m) {
        m.confirmed = true;
        if (m.message->id > confirm_id) confirm_id = m.message->id;
    });

    msg->confirmed_id = confirm_id;

    mSigner.PeerService().Send(pk, msg);

    auto pos = rgs::find_if(mSigner.sent_messages(peer_cache), [&msg](const auto &m) { return *(m.message) == *msg; });
    if (mSigner.sent_messages(peer_cache).end() == pos) {
        mSigner.sent_messages(peer_cache).push_back({msg, false});
    }
}

void FrostState::DefaultPublish(p2p::frost_message_ptr msg)
{
    mSigner.PeerService().Publish(msg);

    rgs::for_each(mSigner.m_peers_cache | vs::transform([](auto& pair)->details::peer_messages&{ return pair.second; }),
                  [this, msg](auto& peer_cache)
    {
        auto pos = rgs::find_if(mSigner.sent_messages(peer_cache), [&msg](const auto &m) { return *(m.message) == *msg; });
        if (mSigner.sent_messages(peer_cache).end() == pos) {
            mSigner.sent_messages(peer_cache).push_back({msg, false});
        }
    });
}

bool FrostState::DefaultReceive(p2p::frost_message_ptr received_msg)
{
    auto& peer_cache = mSigner.m_peers_cache[received_msg->pubkey];

    rgs::for_each(mSigner.sent_messages(peer_cache),
                  [&received_msg](auto& m) { m.confirmed = received_msg->confirmed_id >= m.message->id; });

    auto pos = rgs::find_if(mSigner.received_messages(peer_cache), [&received_msg](const auto &m) { return *(m.message) == *received_msg; });
    if (mSigner.sent_messages(peer_cache).end() == pos) {
        mSigner.SignerService().Accept(move(mSigner.SignerApi()), received_msg);
        mSigner.sent_messages(peer_cache).push_back({received_msg, false});
        return true;
    }

    // else it's a duplicate of some already accepted message
    return false;
}

//====================================================================================================================

struct ProcessSignatureNonces : public FrostState
{
    explicit ProcessSignatureNonces(FrostSigner& s) : FrostState(s) {}

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

    std::unique_ptr<FrostState> GetNextState() const override;
};


struct ProcessKeyCommitments : public FrostState
{
    std::atomic_size_t commitments_received;

    explicit ProcessKeyCommitments(FrostSigner& s) : FrostState(s), commitments_received(0) {}

    const char *Name() const noexcept override
    { return "ProcessKeyCommitments"; }

    bool MessageSend(const std::optional<const xonly_pubkey>&, p2p::frost_message_ptr msg) override
    {
        if (msg->id == p2p::FROST_MESSAGE::KEY_COMMITMENT) {
            DefaultPublish(msg);
            send_status = details::FrostStatus::Completed;
            return true;
        }
        return false;
    }

    bool MessageReceive(p2p::frost_message_ptr msg) override
    {
        if (msg->id == p2p::FROST_MESSAGE::KEY_COMMITMENT) {
            if (DefaultReceive(msg) && ++commitments_received >= mSigner.N) {
                recv_status = details::FrostStatus::Completed;
            }
            return true;
        }
        return false;
    }

    std::unique_ptr<FrostState> GetNextState() const override;
};


struct ProcessKeyShares : public FrostState
{
    std::atomic_size_t keyshares_sent;
    std::atomic_size_t keyshares_received;

    explicit ProcessKeyShares(FrostSigner& s) : FrostState(s), keyshares_sent(0), keyshares_received(0) {}

    const char *Name() const noexcept override
    { return "AggregateKey"; }

    bool MessageSend(const std::optional<const xonly_pubkey>& peer_pk, p2p::frost_message_ptr msg) override
    {
        if (msg->id == p2p::FROST_MESSAGE::KEY_SHARE) {
            DefaultSend(peer_pk.value(), msg);
            if (++keyshares_sent >= mSigner.N) {
                send_status = details::FrostStatus::Completed;
            }
            return true;
        }
        return false;
    }

    bool MessageReceive(p2p::frost_message_ptr msg) override
    {
        if (msg->id == p2p::FROST_MESSAGE::KEY_SHARE) {
            if (DefaultReceive(msg) && ++keyshares_received >= mSigner.N) {
                recv_status = details::FrostStatus::Completed;
            }
            return true;
        }
        return false;
    }

    std::unique_ptr<FrostState> GetNextState() const override;
};


struct ProcessSignatureCommitments : public FrostState
{
    std::atomic_size_t commitments_received;

    explicit ProcessSignatureCommitments(FrostSigner& s) : FrostState(s), commitments_received(0) {}

    const char *Name() const noexcept override
    { return "ProcessSignatureCommitments"; }

    bool MessageSend(const std::optional<const xonly_pubkey>&, p2p::frost_message_ptr msg) override
    {
        if (msg->id == p2p::FROST_MESSAGE::SIGNATURE_COMMITMENT) {
            DefaultPublish(msg);
            send_status = details::FrostStatus::Completed;
            return true;
        }
        return false;
    }

    bool MessageReceive(p2p::frost_message_ptr msg) override
    {
        if (msg->id == p2p::FROST_MESSAGE::SIGNATURE_COMMITMENT) {
            if (DefaultReceive(msg) && ++commitments_received >= mSigner.K) {
                recv_status = details::FrostStatus::Completed;
            }
            return true;
        }
        return false;
    }

    std::unique_ptr<FrostState> GetNextState() const override;
};


struct AggregateSignature : public FrostState
{
    explicit AggregateSignature(FrostSigner& s) : FrostState(s) {}

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
            DefaultReceive(msg);
            return true;
        }
        return false;
    }

    std::unique_ptr<FrostState> GetNextState() const override;

};


template <std::derived_from<FrostState> START_STATE>
class FrostOperationImpl : public details::FrostOperation
{
    FrostSigner& mSigner;

    std::deque<std::unique_ptr<FrostState>> mStepState;
    std::shared_mutex m_state_mutex;

    template<typename CALLABLE, typename... ARGS>
    details::FrostStatus MessageProcImpl(CALLABLE action, ARGS &... args);

public:
    explicit FrostOperationImpl(FrostSigner& s);

    ~FrostOperationImpl() override = default;;

    details::FrostStatus HandleSend(const std::optional<const xonly_pubkey>& peer_pk, p2p::frost_message_ptr m) override
    { return MessageProcImpl(&FrostState::MessageSend, peer_pk, m); }

    details::FrostStatus HandleReceive(p2p::frost_message_ptr m) override
    { return MessageProcImpl(&FrostState::MessageReceive, m); }
};

//====================================================================================================================

std::unique_ptr<FrostState> ProcessSignatureNonces::GetNextState() const
{ return std::unique_ptr<FrostState>(nullptr); }

std::unique_ptr<FrostState> ProcessKeyCommitments::GetNextState() const
{ return std::make_unique<ProcessKeyShares>(mSigner); }

std::unique_ptr<FrostState> ProcessKeyShares::GetNextState() const
{ return std::unique_ptr<FrostState>(nullptr); }

std::unique_ptr<FrostState> ProcessSignatureCommitments::GetNextState() const
{ return std::make_unique<AggregateSignature>(mSigner); }

std::unique_ptr<FrostState> l15::frost::AggregateSignature::GetNextState() const
{ return std::unique_ptr<FrostState>(nullptr); }

//====================================================================================================================

template <std::derived_from<FrostState> START_STATE>
FrostOperationImpl<START_STATE>::FrostOperationImpl(FrostSigner& s)
        : FrostOperation(), mSigner(s), mStepState()
{
    mStepState.emplace_back(std::make_unique<START_STATE>(mSigner));
}


template<std::derived_from<FrostState> START_STATE>
template <typename CALLABLE, typename... ARGS>
details::FrostStatus FrostOperationImpl<START_STATE>::MessageProcImpl(CALLABLE action, ARGS&... args)
{
    details::FrostStatus res = details::FrostStatus::InProgress;
    bool modifyFlag = false;

    {
        std::shared_lock read_lock(m_state_mutex);

        for (auto &stepState: mStepState) {
            //stepState->MessageIsSent(peer_pk, m);
            // or
            //stepState->MessageIsReceived(m);
            modifyFlag |= (stepState.get()->*action)(args...);
        }

        modifyFlag |= mStepState.back()->IsCompleted();
    }

    if (modifyFlag) {
        std::unique_lock lock(m_state_mutex);

        if (mStepState.back()->IsCompleted()) {
            std::unique_ptr<FrostState> nextState = mStepState.back()->GetNextState();
            if (nextState) {
                mStepState.emplace_back(move(nextState));
            }
        }

        while (mStepState.front()->IsConfirmed()) {
            mStepState.pop_front();
        }

        if (mStepState.empty()) {
            res = details::FrostStatus::Completed;
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
            if (op.second->HandleSend(std::make_optional<const xonly_pubkey>(peer_pk), m) == details::FrostStatus::Completed) {
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
            if (op.second->HandleSend(std::make_optional<const xonly_pubkey>(), m) == details::FrostStatus::Completed) {
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
            if (op.second->HandleReceive(m) == details::FrostStatus::Completed) {
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

std::shared_future<const xonly_pubkey&> FrostSigner::AggregateKey()
{
    auto aggpkres = m_aggpk_future.share();
    if (aggpkres.wait_for(std::chrono::microseconds(0)) == std::future_status::ready)
    {
        throw WrongFrostState("conflicting aggpk");
    }

    std::unique_lock oplock(m_op_mutex);

    if(!mOperations.empty())
        throw WrongFrostState("concurent aggpk");

    mOperations.emplace(details::OperationMapId{0, details::OperationType::key}, std::make_unique<FrostOperationImpl<ProcessKeyCommitments>>(*this));

    mSignerService->PublishKeyShareCommitment(mSignerApi);

    return aggpkres;
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

}

}