
#include "signer_service.hpp"
#include "generic_service.hpp"

namespace l15::signer_service {

void SignerService::Accept(std::shared_ptr<core::SignerApi> ps, p2p::frost_message_ptr msg)
{
    ps->Accept(*msg);

    //mBgService->Serve([=](){ ps->Accept(*msg); });
}

std::future<void> SignerService::PublishKeyShareCommitment(std::shared_ptr<core::SignerApi> ps)
{
    std::promise<void> p;
    auto res = p.get_future();

    mBgService->Serve([ps](std::promise<void>&& p1)
                      {
                          ps->CommitKeyShares();
                          p1.set_value();
                      }, move(p));

    return move(res);

}

std::future<const xonly_pubkey&> SignerService::NegotiateKey(std::shared_ptr<core::SignerApi> ps)
{
    std::promise<const xonly_pubkey&> p;
    auto res = p.get_future();

    mBgService->Serve([this, ps](std::promise<const xonly_pubkey&>&& p1)
        {
            ps->DistributeKeyShares([this, ps] (std::promise<const xonly_pubkey&>&& p2)
                {
                    mBgService->Serve([ps](std::promise<const xonly_pubkey&>&& p3)
                    {
                        ps->AggregateKey();
                        p3.set_value(ps->GetAggregatedPubKey());
                    }, move(p2));
                }, move(p1));
        }, move(p));

    return move(res);
}

std::future<void> SignerService::PublishNonces(std::shared_ptr<core::SignerApi> ps, size_t count)
{
    std::promise<void> p;
    auto res = p.get_future();

    mBgService->Serve([ps, count](std::promise<void>&& p1)
        {
            ps->CommitNonces(count);
            p1.set_value();
        }, move(p));

    return move(res);
}

std::future<signature> SignerService::Sign(std::shared_ptr<core::SignerApi> ps, const uint256 &message, core::operation_id opid)
{
    std::promise<signature> p;
    auto res = p.get_future();

    mBgService->Serve([=](std::promise<signature>&& p1)
        {

            auto comm_recv_hdl =  [=]()
            {
                try {
                    ps->PreprocessSignature(message, opid);
                    ps->DistributeSigShares(opid);
                }
                catch(std::exception& e) {
                    // TODO: implement error processing here
                    std::cerr << "Uncaught error: " << e.what() << std::endl;
                }
            };

            auto sigshares_recv_hdl = [=](std::promise<signature>&& p2)
            {
                try {
                    p2.set_value(ps->AggregateSignature(opid));
                }
                catch(...) {
                    p2.set_exception(std::current_exception());
                }
                ps->ClearSignatureCache(opid);
            };

            ps->InitSignature(opid,
                              core::make_callable_with_signer(move(comm_recv_hdl)),
                              core::make_callable_with_signer(move(sigshares_recv_hdl), move(p1))
            );
        }, move(p));

    return move(res);
}


} // l15