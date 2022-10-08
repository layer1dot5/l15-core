
#include "signer_service.hpp"
#include "signer_api.hpp"
#include "generic_service.hpp"

namespace l15::signer_service {

//TODO: Add try/catch and assign to promise at lambdas


std::future<const xonly_pubkey&> SignerService::NegotiateKey(const xonly_pubkey &signer_key)
{
    auto& ps = m_signers[&signer_key];

    return mBgService.Serve<const xonly_pubkey&>(
        [&](std::promise<const xonly_pubkey&>&& p)
        {
            ps->DistributeKeyShares(
                [&] (core::SignerApi& s, std::promise<const xonly_pubkey&>&& p1)
                {
                    std::function<void(std::promise<const xonly_pubkey&>&&)> aggregate =
                            [&](std::promise<const xonly_pubkey&>&& p2)->void
                            {
                                s.AggregateKey();
                                p2.set_value(s.GetAggregatedPubKey());
                            };

                    mBgService.Serve(aggregate, move(p1));

                }, move(p)
            );
        }
    );

}

std::future<void> SignerService::PublishNonces(const xonly_pubkey &signer_key, size_t count)
{
    auto& s = m_signers[&signer_key];

    return mBgService.Serve([&]()
    {
        s->CommitNonces(count);
    });
}

std::future<signature> SignerService::Sign(const xonly_pubkey &signer_key, const uint256 &message, core::operation_id opid)
{
    auto ps = m_signers[&signer_key];

    return mBgService.Serve<signature>([&](std::promise<signature>&& p)
    {
        ps->InitSignature(opid,
                          core::make_callable(
                                [&](core::SignerApi& s, const core::operation_id& opid)
                                {
                                    mBgService.Serve([&]() {
                                        s.PreprocessSignature(message, opid);
                                        s.DistributeSigShares(opid);
                                    });
                                },
                                core::operation_id(opid)),
                          core::make_callable(
                                [&](core::SignerApi& s, const core::operation_id& opid, std::promise<signature>&& p1)
                                {
                                    std::function<void(std::promise<signature>&&)> aggregate =
                                            [&](std::promise<signature>&& p1)
                                            {
                                                p1.set_value(s.AggregateSignature(opid));
                                                s.ClearSignatureCache(opid);
                                            };

                                    mBgService.Serve(aggregate, move(p1));
                                },
                          core::operation_id(opid), move(p))
                          );
    });
}


} // l15