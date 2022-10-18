
#include "zmq_context.hpp"

namespace l15::service {

std::optional<zmq::context_t> ZmqContextSingleton::zmq_ctx;
std::mutex ZmqContextSingleton::zmq_mutex;
std::string ZmqContextSingleton::STOP("stop");

}