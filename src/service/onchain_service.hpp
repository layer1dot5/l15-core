#pragma once

#include <memory>
#include <optional>
#include <thread>

#include <zmq.hpp>

#include "chain_api.hpp"


namespace l15::chain_service {


namespace details {

struct OnChainServiceBase {
    static std::optional<zmq::context_t> zmq_ctx;

    OnChainServiceBase() {
        if (!zmq_ctx.has_value()) {
            zmq_ctx.emplace(zmq::context_t());
        }
    }
};

}

class OnChainService : protected details::OnChainServiceBase
{

    std::unique_ptr<core::ChainApi> mChain;
    std::thread mThread;



    void MainCycle(std::string addr);

public:
    explicit OnChainService(std::unique_ptr<core::ChainApi>&& chain)
        : details::OnChainServiceBase(), mChain(std::move(chain))
    {}

    const core::ChainApi& ChainAPI() const
    { return *mChain; }

    void Start();
    void Stop();

    void CommitNonces();

};

} // l15
