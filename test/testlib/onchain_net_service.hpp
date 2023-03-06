#pragma once

#include <memory>

#include <tbb/concurrent_vector.h>
#include <boost/container/flat_map.hpp>

#include "common.hpp"
#include "zmq_context.hpp"
#include "p2p_frost.hpp"
#include "p2p_link.hpp"
#include "zmq_service.hpp"

namespace l15::p2p {

    class OnChainService: public P2PInterface<xonly_pubkey, p2p::FrostMessage>  {

    };

}