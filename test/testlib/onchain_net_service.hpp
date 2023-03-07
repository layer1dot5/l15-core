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

    class AbstractOnChainProtocol {
    public:
        AbstractOnChainProtocol() = default;
        virtual ~AbstractOnChainProtocol() = default;

        virtual void GetVersion() = 0;

        virtual void ReadTransaction() = 0;
        virtual void WriteTransaction() = 0;
    };

    class AbstractOnChainWriter {
    public:
        AbstractOnChainWriter() = default;
        virtual ~AbstractOnChainWriter() = default;

        virtual void Write() = 0;
    };

    class OnChainWriter: public AbstractOnChainWriter {
    public:
        void Write() override;
    };

    class AbstractOnChainReader {
    public:
        AbstractOnChainReader() = default;
        virtual ~AbstractOnChainReader() = default;

        virtual void Read() = 0;
    };

    class OnChainService: public P2PInterface<xonly_pubkey, p2p::FrostMessage>  {
    public:
        explicit OnChainService(const secp256k1_context_struct *ctx, std::shared_ptr<service::GenericService> srv, std::function<bool(p2p::frost_message_ptr)> msg_filter = [](p2p::frost_message_ptr){ return true;})
                : m_ctx(ctx), zmq_ctx(zmq::context_t(10)), m_peers(), mTaskService(move(srv)), m_protocol_confirmation_mutex(), m_exit_mutex(), m_message_filter(move(msg_filter)) {}

        ~OnChainService() override;

        void AddPeer(xonly_pubkey&& pk, string&& addr);

        const ZmqService::peers_map& GetPeersMap() const;

        const std::function<void(p2p::frost_message_ptr)>& GetMessageHandler();

        void Publish(p2p::frost_message_ptr m,
                     std::function<void(const xonly_pubkey&, p2p::frost_message_ptr)> on_send,
                     std::function<void(const xonly_pubkey&, p2p::frost_message_ptr)> on_error) override;

        void Send(const xonly_pubkey& pk, p2p::frost_message_ptr m,
                  std::function<void()> on_error) override;

        void Connect(const xonly_pubkey&, std::function<void(p2p::frost_message_ptr)>) override;

        void WaitForConfirmations();
    private:
        ZmqService::Ptr m_zmq;
    };

} // namespace l15::p2p