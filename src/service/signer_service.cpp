
#include "signer_service.hpp"
#include "signer_api.hpp"

namespace l15::signer_service {

namespace
{

    core::general_handler key_hdl = [](core::SignerApi& s) { s.AggregateKey(); };

}


SignerService::SignerService() : mSigners()
{

}

std::future<xonly_pubkey&> SignerService::NegotiateKey(std::shared_ptr<core::SignerApi> signer)
{
    std::promise<xonly_pubkey&> res;

    try {
        if (!mSigners.insert(make_pair(signer->GetLocalPubKey(), signer)).second) {
            // Lets not to throw, just start to work with signer we already have
            //throw service::IllegalServiceParameterError("");

        }


    }catch (...)
    {
        res.set_exception(std::current_exception());
    }

    return res.get_future();
}

std::future<void> SignerService::MakeNonces(const xonly_pubkey &signer_key, size_t count)
{
    return std::future<void>();
}

std::future<signature> SignerService::Sign(const xonly_pubkey &signer_key, const uint256 &message)
{
    return std::future<signature>();
}

void SignerService::DisposeSigner(const xonly_pubkey &signer_key)
{

}

} // l15