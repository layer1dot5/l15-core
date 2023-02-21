#pragma once

#include <memory>
#include <ranges>
#include <future>
#include <deque>
#include <map>

#include <tbb/concurrent_priority_queue.h>

#include "common.hpp"
#include "common_error.hpp"
#include "uint256.h"
#include "channel_keys.hpp"
#include "signer_api.hpp"
#include "signer_service.hpp"

#include "frost_common.hpp"
#include "frost_steps.hpp"

namespace l15::frost {

// FrostSigner API is currently WIP prototype.
// The main focus is at internal state machine so far.




class FrostOperationBase
{
    std::deque<std::shared_ptr<FrostStep>> mSteps;
public:
    explicit FrostOperationBase(std::shared_ptr<FrostStep> startStep)
    {
        mSteps.emplace_back(startStep);
        while (auto step = mSteps.back()->GetNextStep()) {
            mSteps.emplace_back(move(step));
        }
    }

    virtual ~FrostOperationBase() = default;

    std::deque<std::shared_ptr<FrostStep>>& Steps()
    { return mSteps; }

    template <std::derived_from<FrostStep> STEP, typename RES, std::derived_from<cex::async_result_base<RES>> RES_HANDLER, typename ... ARGS>
    void Start(RES_HANDLER&& handler, ARGS&& ... args)
    {
        try {
            FrostStep &s = *(mSteps.front());
            STEP &startStep = dynamic_cast<STEP &>(s);
            return startStep.Start(cex::make_async_result<RES>([](RES&& res, RES_HANDLER&& handler){
                    handler(std::forward<RES>(res));
                },[opid = startStep.OperatonId()](RES_HANDLER&& handler){
                    try {
                        std::throw_with_nested(FrostOperationFailure(opid));
                    }
                    catch(...) {
                        handler.on_error();
                    }
            }, std::forward<RES_HANDLER>(handler)), std::forward<ARGS>(args)...);
        }
        catch(...) {
            std::throw_with_nested(FrostOperationFailure(mSteps.front()->OperatonId()));
        }
    }

    template <std::derived_from<FrostStep> STEP, std::derived_from<cex::async_result_base<void>> RES_HANDLER, typename ... ARGS>
    void Start(RES_HANDLER&& handler, ARGS&& ... args)
    {
        try {
            FrostStep &s = *(mSteps.front());
            STEP &startStep = dynamic_cast<STEP &>(s);
            return startStep.Start(cex::make_async_result<void>([](RES_HANDLER&& handler){
                handler();
            },[opid = startStep.OperatonId()](RES_HANDLER&& handler){
                try {
                    std::throw_with_nested(FrostOperationFailure(opid));
                }
                catch(...) {
                    handler.on_error();
                }
            }, std::forward<RES_HANDLER>(handler)), std::forward<ARGS>(args)...);
        }
        catch(...) {
            std::throw_with_nested(FrostOperationFailure(mSteps.front()->OperatonId()));
        }
    }

    virtual bool CheckAndQueueSendingMessage(FrostSigner &signer, const std::optional<const xonly_pubkey> &peer_pk, p2p::frost_message_ptr m)=0;
    virtual FrostStatus HandleSend(FrostSigner& signer, const std::optional<const xonly_pubkey> &peer_pk)=0;
    virtual bool CheckAndQueueReceivedMessage(FrostSigner &signer, p2p::frost_message_ptr m)=0;
    virtual FrostStatus HandleReceive(FrostSigner& signer, const xonly_pubkey &peer_pk)=0;
};


class FrostSigner : public FrostSignerBase, public std::enable_shared_from_this<FrostSigner>
{
    friend class FrostOperation;
    friend class FrostStep;
    friend class NonceCommit;
    friend class KeyCommit;
    friend class KeyShare;
    friend class SigCommit;
    friend class SigAgg;

    std::map<details::OperationMapId, std::shared_ptr<FrostOperationBase>> mOperations;
    std::shared_mutex m_op_mutex;

    std::function<void()> m_error_handler = [](){};

private:


    void Send(const xonly_pubkey& peer_pk, p2p::frost_message_ptr m);
    void Publish(p2p::frost_message_ptr m);
    void HandleError() override;

    void Receive(p2p::frost_message_ptr m);

    std::shared_ptr<FrostOperationBase> NewKeyAgg();
    std::shared_ptr<FrostOperationBase> GetCommitNonces();
    std::shared_ptr<FrostOperationBase> NewSign(uint256 message, core::operation_id opid);

public:

    explicit FrostSigner(
            core::ChannelKeys keypair, std::ranges::input_range auto&& peers,
            std::shared_ptr<signer_service::SignerService> signerService,
            std::shared_ptr<p2p::P2PInterface<xonly_pubkey, p2p::FrostMessage>> peerService)
            : FrostSignerBase(keypair, peers, signerService, peerService)
            , mOperations(), m_op_mutex()
    {}

    ~FrostSigner() override;

    void SetErrorHandler(std::function<void()> h)
    { m_error_handler = h; }

    void Start();

    template <std::derived_from<cex::async_result_base<const xonly_pubkey&>> RES>
    void AggregateKey(RES&& handler)
    { NewKeyAgg()->Start<KeyCommit, const xonly_pubkey&>(std::forward<RES>(handler)); }

    template <std::derived_from<cex::async_result_base<void>> RES>
    void CommitNonces(size_t count, RES&& handler)
    { GetCommitNonces()->Start<NonceCommit>(std::forward<RES>(handler), count); }

    template <std::derived_from<cex::async_result_base<signature>> RES>
    void Sign(uint256 message, core::operation_id opid, RES&& handler)
    { NewSign(message, opid)->Start<SigCommit, signature>(std::forward<RES>(handler)); }

    void Verify(uint256 message, signature sig) const;
};

}