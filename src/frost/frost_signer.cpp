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


//====================================================================================================================


//====================================================================================================================

class FrostOperation : public FrostOperationBase
{

    template<typename CALLABLE, typename... ARGS>
    bool MessageQueueImpl(CALLABLE action, ARGS&&... args);

    template<typename CALLABLE, typename... ARGS>
    FrostStatus MessageProcImpl(CALLABLE action, ARGS&&... args);

public:
    explicit FrostOperation(std::shared_ptr<FrostStep> startStep): FrostOperationBase(startStep)
    { }

    bool CheckAndQueueSendingMessage(FrostSigner &signer, const std::optional<const xonly_pubkey> &peer_pk, p2p::frost_message_ptr m) override
    { return MessageQueueImpl(&FrostStep::CheckAndQueueSend, signer, peer_pk, m); }

    FrostStatus HandleSend(FrostSigner& signer, const std::optional<const xonly_pubkey> &peer_pk) override
    { return MessageProcImpl(&FrostStep::MessageSend, signer, peer_pk); }

    bool CheckAndQueueReceivedMessage(FrostSigner &signer, p2p::frost_message_ptr m) override
    { return MessageQueueImpl(&FrostStep::CheckAndQueueReceive, signer, m); }

    FrostStatus HandleReceive(FrostSigner& signer, const xonly_pubkey &peer_pk) override
    { return MessageProcImpl(&FrostStep::MessageReceive, signer, peer_pk); }
};

//====================================================================================================================

template <typename CALLABLE, typename... ARGS>
bool FrostOperation::MessageQueueImpl(CALLABLE action, ARGS&&... args)
{
    for (auto& step: Steps()) {
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
    check_steps.reserve(Steps().size());

    for (const auto& step: Steps()) {
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
{ m_error_handler(); }

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
    mSignerApi->SetErrorHandler([ws](){
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

    details::OperationMapId opid {core::operation_id(0), details::OperationType::nonce};
    mOperations.emplace(opid, std::make_shared<FrostOperation>(std::make_shared<NonceCommit>(shared_from_this(), opid)));
}

std::shared_ptr<FrostOperationBase> FrostSigner::NewKeyAgg()
{
    details::OperationMapId opid {core::operation_id(0), details::OperationType::key};
    auto op = std::make_shared<FrostOperation>(std::make_shared<KeyCommit>(this->shared_from_this(), opid));

    std::unique_lock oplock(m_op_mutex);

    if(mOperations.size() > 1)
        throw WrongFrostState("concurent aggpk??");

    auto opres = mOperations.emplace(opid, op);

    if (!opres.second) {
        throw FrostOperationFailure(opid);
    }

    return op;
}

std::shared_ptr<FrostOperationBase> FrostSigner::GetCommitNonces()
{
    details::OperationMapId opid {core::operation_id(0), details::OperationType::nonce};
    std::unique_lock oplock(m_op_mutex);
    return mOperations[opid];
}

std::shared_ptr<FrostOperationBase> FrostSigner::NewSign(const scalar& message, const core::operation_id& opid)
{
    details::OperationMapId opmapid {opid, details::OperationType::sign};

    auto op = std::make_shared<FrostOperation>(std::make_shared<SigCommit>(this->shared_from_this(), opmapid, message));

    std::unique_lock oplock(m_op_mutex);
    auto opres = mOperations.emplace(opmapid, op);

    if (!opres.second) {
        throw FrostOperationFailure(opmapid);
    }

    return op;
}

void FrostSigner::Verify(const scalar& message, const signature& sig) const
{ mSignerApi->Verify(message, sig); }

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
        return (std::ostringstream() << "sign/" << hex(opid)).str();
    }
    throw std::runtime_error((std::ostringstream() << "Wrong optype: " << static_cast<uint16_t>(optype)).str());
}

} // namespace details

}