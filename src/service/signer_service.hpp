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
    std::shared_ptr<service::GenericService> mBgService;

public:
    explicit SignerService(std::shared_ptr<service::GenericService> bgService) : mBgService(move(bgService)) {}

    void Accept(std::shared_ptr<core::SignerApi> ps, p2p::frost_message_ptr msg);

    std::future<void> PublishKeyShareCommitment(std::shared_ptr<core::SignerApi> signer);
    std::future<const xonly_pubkey&> NegotiateKey(std::shared_ptr<core::SignerApi> signer);
    std::future<void> PublishNonces(std::shared_ptr<core::SignerApi> signer, size_t count);
    std::future<signature> Sign(std::shared_ptr<core::SignerApi> signer, const uint256 &message, core::operation_id opid);

};

} // namespace signing_service
} // namespace l15
