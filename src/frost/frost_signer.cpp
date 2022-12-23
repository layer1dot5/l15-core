#include "frost_signer.hpp"

#include <algorithm>
#include <deque>

#include <tbb/concurrent_unordered_map.h>


namespace l15::frost {

namespace {

//====================================================================================================================

struct FrostMessageSM
{

};

struct FrostState
{
    tbb::concurrent_unordered_map<xonly_pubkey, std::pair<std::unique_ptr<FrostMessageSM>, std::unique_ptr<FrostMessageSM>>, l15::hash<xonly_pubkey>> in_out_state;
    details::FrostStatus status;

    FrostState() : status(details::FrostStatus::InProgress)
    {}

    virtual ~FrostState() = default;

    virtual const char *Name() const noexcept = 0;

    virtual void MessageIsSent(const std::optional<const xonly_pubkey>&, p2p::frost_message_ptr) = 0;

    virtual void MessageIsReceived(p2p::frost_message_ptr) = 0;

    virtual std::unique_ptr<FrostState> GetNextState() const = 0;
};


struct ProcessKeyCommitments : public FrostState
{
    const char *Name() const noexcept override
    { return "ProcessKeyCommitments"; }

    void MessageIsSent(const std::optional<const xonly_pubkey>&, p2p::frost_message_ptr) override;

    void MessageIsReceived(p2p::frost_message_ptr) override;

    std::unique_ptr<FrostState> GetNextState() const override;
};


struct AggregateKey : public FrostState
{
    const char *Name() const noexcept override
    { return "AggregateKey"; }

    void MessageIsSent(const std::optional<const xonly_pubkey>&, p2p::frost_message_ptr) override;

    void MessageIsReceived(p2p::frost_message_ptr) override;

    std::unique_ptr<FrostState> GetNextState() const override;
};


struct ProcessSignatureCommitments : public FrostState
{
    const char *Name() const noexcept override
    { return "ProcessSignatureCommitments"; }

    void MessageIsSent(const std::optional<const xonly_pubkey>&, p2p::frost_message_ptr) override;

    void MessageIsReceived(p2p::frost_message_ptr) override;

    std::unique_ptr<FrostState> GetNextState() const override;

};

struct AggregateSignature : public FrostState
{
    const char *Name() const noexcept override
    { return "AggregateSignature"; }

    void MessageIsSent(const std::optional<const xonly_pubkey>&, p2p::frost_message_ptr) override;

    void MessageIsReceived(p2p::frost_message_ptr) override;

    std::unique_ptr<FrostState> GetNextState() const override;

};


struct FrostSMImpl : details::FrostSM
{
    std::deque<std::unique_ptr<FrostState>> mStepState;
    std::shared_mutex m_state_mutex;

    explicit FrostSMImpl(std::weak_ptr<details::FrostSignerInterface> &&signer, std::unique_ptr<FrostState> &&startState);

    ~FrostSMImpl() override = default;

    details::FrostStatus MessageIsSent(const std::optional<const xonly_pubkey>& , p2p::frost_message_ptr m) override;

    details::FrostStatus MessageIsReceived(p2p::frost_message_ptr m) override;

    template<typename CALLABLE, typename... ARGS>
    details::FrostStatus MessageProcImpl(CALLABLE action, ARGS &... args);
};


//====================================================================================================================


void l15::frost::ProcessKeyCommitments::MessageIsSent(const std::optional<const xonly_pubkey>&, p2p::frost_message_ptr)
{

}

void l15::frost::ProcessKeyCommitments::MessageIsReceived(p2p::frost_message_ptr)
{

}

std::unique_ptr<FrostState> l15::frost::ProcessKeyCommitments::GetNextState() const
{ return std::make_unique<AggregateKey>(); }


void l15::frost::AggregateKey::MessageIsSent(const std::optional<const xonly_pubkey>&, p2p::frost_message_ptr)
{

}

void l15::frost::AggregateKey::MessageIsReceived(p2p::frost_message_ptr)
{

}

std::unique_ptr<FrostState> l15::frost::AggregateKey::GetNextState() const
{
    return std::unique_ptr<FrostState>();
}

FrostSMImpl::FrostSMImpl(std::weak_ptr<details::FrostSignerInterface> &&signer, std::unique_ptr<FrostState> &&startState)
        : FrostSM(move(signer)), mStepState()
{
    mStepState.emplace_back(move(startState));
}

}
//====================================================================================================================

template<typename CALLABLE, typename... ARGS>
details::FrostStatus l15::frost::FrostSMImpl::MessageProcImpl(CALLABLE action, ARGS&... args)
{
    details::FrostStatus res = details::FrostStatus::InProgress;
    bool modifyFlag = false;

    {
        std::shared_lock read_lock(m_state_mutex);

        for (auto &stepState: mStepState) {
            //stepState->MessageIsSent(move(peer_pk), m);
            (stepState.get()->*action)(args...);
            modifyFlag |= (stepState->status == details::FrostStatus::Completed);
        }

        modifyFlag |= (mStepState.back()->status == details::FrostStatus::Completed);
    }

    if (modifyFlag) {
        std::unique_lock lock(m_state_mutex);

        if (mStepState.back()->status != details::FrostStatus::InProgress) {
            std::unique_ptr<FrostState> nextState = mStepState.back()->GetNextState();
            if (nextState) {
                mStepState.emplace_back(move(nextState));
            }
        }

        while (mStepState.front()->status == details::FrostStatus::Confirmed) {
            mStepState.pop_front();
        }

        if (mStepState.empty()) {
            res = details::FrostStatus::Completed;
        }
    }

    return res;

}

details::FrostStatus FrostSMImpl::MessageIsSent(const std::optional<const xonly_pubkey>& peer_pk, p2p::frost_message_ptr m)
{
    return MessageProcImpl(&FrostState::MessageIsSent, peer_pk, m);
}

details::FrostStatus l15::frost::FrostSMImpl::MessageIsReceived(p2p::frost_message_ptr m)
{
    return MessageProcImpl(&FrostState::MessageIsReceived, m);
}
//====================================================================================================================


void FrostSigner::HandleSendToPeer(const xonly_pubkey &peer_pk, p2p::frost_message_ptr m)
{
    mPeerService->Send(peer_pk, m);

    std::vector<core::operation_id> completed;
    {
        std::shared_lock oplock(m_op_mutex);

        std::for_each(mOperations.begin(), mOperations.end(), [&](auto &op) {
            if (op.second->MessageIsSent(std::make_optional<const xonly_pubkey>(peer_pk), m) == details::FrostStatus::Completed) {
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
    mPeerService->Publish(m);

    std::vector<core::operation_id> completed;
    {
        std::shared_lock oplock(m_op_mutex);

        std::for_each(mOperations.begin(), mOperations.end(), [&](auto &op) {
            if (op.second->MessageIsSent(std::make_optional<const xonly_pubkey>(), m) == details::FrostStatus::Completed) {
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
    mSignerService->Accept(mSignerApi, m);

    std::vector<core::operation_id> completed;
    {
        std::shared_lock oplock(m_op_mutex);

        std::for_each(mOperations.begin(), mOperations.end(), [&](auto &op) {
            if (op.second->MessageIsReceived(m) == details::FrostStatus::Completed) {
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

void FrostSigner::StartKeyAgg()
{
    auto aggpkres = m_aggpk_future.share();
    if (aggpkres.wait_for(std::chrono::microseconds(0)) == std::future_status::ready)
    {
        throw WrongFrostState("conflicting aggpk");
    }

    std::unique_lock oplock(m_op_mutex);

    if(!mOperations.empty())
        throw WrongFrostState("concurent aggpk");

    mOperations.emplace(0, std::make_unique<FrostSMImpl>(shared_from_this(), std::make_unique<ProcessKeyCommitments>()));

    mSignerService->PublishKeyShareCommitment(mSignerApi);
}

}