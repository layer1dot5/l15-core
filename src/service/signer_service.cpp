
#include "signer_service.hpp"
#include "generic_service.hpp"

namespace l15::signer_service {

void SignerService::Accept(const xonly_pubkey &pk, p2p::frost_message_ptr msg)
{
    auto it = m_signers.find(&pk);
    if (it != m_signers.end()) {
        std::shared_ptr<core::SignerApi> signer = it->second;

        signer->Accept(*msg);

        //mBgService->Serve([=](){ signer->Accept(*msg); });
    }
}


std::future<const xonly_pubkey&> SignerService::NegotiateKey(const xonly_pubkey &signer_key)
{
    auto ps = m_signers[&signer_key];

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

std::future<void> SignerService::PublishNonces(const xonly_pubkey &signer_key, size_t count)
{
    auto ps = m_signers[&signer_key];

    std::promise<void> p;
    auto res = p.get_future();

    mBgService->Serve([ps, count](std::promise<void>&& p1)
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