
#include "signer_service.hpp"
#include "generic_service.hpp"

namespace l15::signer_service {

void SignerService::Accept(std::shared_ptr<core::SignerApi> ps, p2p::frost_message_ptr msg)
{
    ps->Accept(*msg);

    //mBgService->Serve([=](){ ps->Accept(*msg); });
}


} // l15