//
// Created by lexis on 22.09.22.
//

#include "generic_service.hpp"

namespace l15::signer_service {



}

std::future<void> l15::service::GenericService::Serve(std::function<void()> action, std::function<void()> complete_handler,
                                                      std::function<void(Error && )> error_handler)
{
    return std::future<void>();
}
// l15

