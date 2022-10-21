
#include "zmq_context.hpp"

namespace l15::service {

std::optional<zmq::context_t> ZmqContextSingleton::zmq_ctx;
std::mutex ZmqContextSingleton::zmq_mutex;
std::string ZmqContextSingleton::STOP("stop");

ZmqContextSingleton::ZmqContextSingleton()
{
    std::lock_guard<std::mutex> lock(zmq_mutex);

    if (!zmq_ctx.has_value()) {
        zmq_ctx.emplace(zmq::context_t(10, 10050));
    }
}

}