#pragma once

#include <future>
#include <memory>
#include <map>

#include "common.hpp"
#include "generic_service.hpp"

namespace l15 {

namespace core {

class SignerApi;

}

namespace signer_service {

class SignerService
{
    std::unordered_map<xonly_pubkey, std::shared_ptr<core::SignerApi>, l15::hash<xonly_pubkey>> mSigners;
public:
    SignerService();
    std::future<xonly_pubkey&> NegotiateKey(std::shared_ptr<core::SignerApi> signer);
    std::future<void> MakeNonces(const xonly_pubkey& signer_key, size_t count);
    std::future<signature> Sign(const xonly_pubkey& signer_key, const uint256& message);
    void DisposeSigner(const xonly_pubkey& signer_key);
};

} // namespace signing_service
} // namespace l15
