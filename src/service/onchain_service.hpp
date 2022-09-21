#pragma once

#include <memory>
#include <optional>
#include <thread>

#include <utility>
#include <zmq.hpp>

#include "primitives/block.h"

#include "chain_api.hpp"


namespace l15::onchain_service {


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

    std::function<void(const CBlockHeader& )> m_block_handler;
    std::function<void(const CTransaction& )> m_tx_handler;

    std::thread mThread;

    void MainCycle(std::string addr);

public:
    explicit OnChainService(std::unique_ptr<core::ChainApi>&& chain) :
            details::OnChainServiceBase(),
            mChain(std::move(chain)) {}

    const core::ChainApi& ChainAPI() const
    { return *mChain; }

    void SetNewBlockHandler(std::function<void(const CBlockHeader& )>&& h)
    { m_block_handler = move(h); }

    void SetNewTxHandler(std::function<void(const CTransaction& )>&& h)
    { m_tx_handler = move(h); }

    void Start();
    void Stop();

};

} // l15
