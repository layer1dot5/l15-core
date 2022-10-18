#pragma once

#include <mutex>
#include <optional>
#include <zmq.hpp>

namespace l15::service {

struct ZmqContextSingleton {
    static std::optional<zmq::context_t> zmq_ctx;
    static std::mutex zmq_mutex;

    static std::string STOP;


    ZmqContextSingleton() {

        std::lock_guard<std::mutex> lock(zmq_mutex);

        if (!zmq_ctx.has_value()) {
            zmq_ctx.emplace(zmq::context_t());
        }
    }

    virtual ~ZmqContextSingleton() = default;
};

}