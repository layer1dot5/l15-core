#pragma once

#include <mutex>
#include <optional>
#include <zmq.hpp>

namespace l15::service {

struct ZmqContextSingleton {
    static std::optional<zmq::context_t> zmq_ctx;
    static std::mutex zmq_mutex;

    static std::string STOP;


    ZmqContextSingleton();

    virtual ~ZmqContextSingleton() = default;
};

}