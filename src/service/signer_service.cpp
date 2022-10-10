
#include "signer_service.hpp"
#include "signer_api.hpp"
#include "generic_service.hpp"

namespace l15::signer_service {


std::future<const xonly_pubkey&> SignerService::NegotiateKey(const xonly_pubkey &signer_key)
{
    auto ps = m_signers[&signer_key];

    std::promise<const xonly_pubkey&> p;
    auto res = p.get_future();

    mBgService.Serve([this, ps](std::promise<const xonly_pubkey&>&& p1)
        {
            ps->DistributeKeyShares([this, ps] (std::promise<const xonly_pubkey&>&& p2)
                {
                    mBgService.Serve([ps](std::promise<const xonly_pubkey&>&& p3)
                    {
                        ps->AggregateKey();
                        p3.set_value(ps->GetAggregatedPubKey());
                    }, move(p2));
                }, move(p1));
        }, move(p));

    return move(res);
}

std::future<void> SignerService::PublishNonces(const xonly_pubkey &signer_key, size_t count)
{
    auto ps = m_signers[&signer_key];

    std::promise<void> p;
    auto res = p.get_future();

    mBgService.Serve([ps, count](std::promise<void>&& p1)
        {
            ps->CommitNonces(count);
            p1.set_value();
        }, move(p));

    return move(res);
}

std::future<signature> SignerService::Sign(const xonly_pubkey &signer_key, const uint256 &message, core::operation_id opid)
{

    auto ps = m_signers[&signer_key];

    std::promise<signature> p;
    auto res = p.get_future();

    mBgService.Serve([this, ps, opid, message](std::promise<signature>&& p1)
        {

            auto comm_recv_hdl =  [this, ps, opid, message]()
            {
                auto preproc_action = [ps, opid, message]() {
                    ps->PreprocessSignature(message, opid);
                    ps->DistributeSigShares(opid);
                };
                mBgService.Serve(preproc_action);
            };

            auto sigshares_recv_hdl = [this, ps, opid](std::promise<signature>&& p1)
            {
                mBgService.Serve([ps, opid](std::promise<signature> p2)
                {
                    p2.set_value(ps->AggregateSignature(opid));
                    ps->ClearSignatureCache(opid);
                }, move(p1));

            };

            ps->InitSignature(opid,
                              core::make_callable_with_signer(move(comm_recv_hdl)),
                              core::make_callable_with_signer(move(sigshares_recv_hdl), move(p1))
            );
        }, move(p));

    return move(res);
}


} // l15