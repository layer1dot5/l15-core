//
// Created by lexis on 22.09.22.
//

#include "p2p_service.hpp"

namespace l15::p2p_service {

P2PService::P2PService(std::string addr, std::function<void(const Message &)> handler)
{

}

link_ptr P2PService::GetLink(std::string addr)
{
    return l15::p2p::link_ptr();
}


} // l15::p2p_service
