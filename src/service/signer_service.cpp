
#include "signer_service.hpp"
#include "signer_api.hpp"
#include "generic_service.hpp"

namespace l15::signer_service {


SignerService::SignerService(service::GenericService& bgService) : mBgService(bgService), m_signers()
{

}



std::future<const xonly_pubkey&> SignerService::NegotiateKey(const xonly_pubkey &signer_key)
{
    auto& s = m_signers[&signer_key];

    return mBgService.Serve<const xonly_pubkey&>([&](std::promise<const xonly_pubkey&>&& p)
    {
        s->DistributeKeyShares([&](core::SignerApi& s)
        {
            s.AggregateKey();
            p.set_value(s.GetAggregatedPubKey());
        });
    });

}

std::future<void> SignerService::PublishNonces(const xonly_pubkey &signer_key, size_t count)
{
    auto& s = m_signers[&signer_key];

    return mBgService.Serve([&]()
    {
        s->CommitNonces(count);
    });
}

std::future<signature> SignerService::Sign(const xonly_pubkey &signer_key, const uint256 &message)
{
    return std::future<signature>();
}


} // l15