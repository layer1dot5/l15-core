#pragma once

#include <memory>
#include <optional>
#include <thread>

#include <utility>

#include "primitives/block.h"

#include "chain_api.hpp"
#include "zmq_context.hpp"


namespace l15::onchain_service {


class OnChainService : protected service::ZmqContextSingleton
{

    std::unique_ptr<core::ChainApi> mChain;

    std::function<void(const CBlockHeader& )> m_block_handler;
    std::function<void(const CTransaction& )> m_tx_handler;

    std::thread mThread;

    void MainCycle(std::string&& addr);

public:
    explicit OnChainService(std::unique_ptr<core::ChainApi>&& chain) :
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
