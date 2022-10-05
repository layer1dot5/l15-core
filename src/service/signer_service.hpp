#pragma once

#include <future>
#include <memory>
#include <map>
#include <mutex>

#include "common.hpp"
#include "signer_api.hpp"

namespace l15 {

namespace service {
class GenericService;
}

namespace signer_service {

class SignerService
{
    service::GenericService& mBgService;
    std::unordered_map<const xonly_pubkey*, std::shared_ptr<core::SignerApi>, l15::hash<xonly_pubkey*>, l15::equal_to<xonly_pubkey*>> m_signers;
public:
    SignerService(service::GenericService& bgService);

    void AddSigner(std::shared_ptr<core::SignerApi> signer)
    { m_signers.emplace(&(signer->GetLocalPubKey()), move(signer)); }

    void DisposeSigner(const xonly_pubkey& signer_key)
    { m_signers.erase(&signer_key); }

    std::future<const xonly_pubkey&> NegotiateKey(const xonly_pubkey& signer_key);
    std::future<void> PublishNonces(const xonly_pubkey& signer_key, size_t count);
    std::future<signature> Sign(const xonly_pubkey& signer_key, const uint256& message);
};

} // namespace signing_service
} // namespace l15
