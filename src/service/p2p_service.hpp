#pragma once

#include <string>
#include <functional>
#include <memory>


#include "p2p_link.hpp"
#include "generic_service.hpp"

namespace l15::p2p_service {

using namespace l15::p2p;

class P2PService
{
    service::GenericService mService;
public:
    P2PService(std::string addr, std::function<void(const Message&)> handler);
    ~P2PService() = default;

    link_ptr GetLink(std::string addr);

};

} // l15::p2p_service

