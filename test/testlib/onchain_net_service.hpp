#pragma once

#include <string>
#include <memory>
#include <unordered_map>

#include <tbb/concurrent_vector.h>
#include <boost/container/flat_map.hpp>

#include "common.hpp"
#include "p2p_frost.hpp"
#include "p2p_link.hpp"
#include "chain_api.hpp"
#include "wallet_api.hpp"
#include "zmq_context.hpp"
#include "zmq_service.hpp"
#include "../../src/tools/config.hpp"

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

        virtual void Write(const std::string &payload) = 0;
    };

    class OnChainWriterV1: public AbstractOnChainWriter {
    public:
        OnChainWriterV1(const l15::Config &config);
        void Write(const std::string &payload) override;
        OnChainWriterV1& operator<<(const std::string &payload);
    private:
        core::WalletApi m_wallet;
        std::unique_ptr<core::ChainApi> m_chainApi;
    };

    class AbstractOnChainReader {
    public:
        AbstractOnChainReader() = default;
        virtual ~AbstractOnChainReader() = default;

        virtual void Read() = 0;
    };

    class OnChainService: public P2PInterface<xonly_pubkey, p2p::FrostMessage>  {
    public:
        explicit OnChainService(const secp256k1_context_struct *ctx,
                                std::shared_ptr<service::GenericService> srv,
                                std::function<bool(p2p::frost_message_ptr)> msg_filter = [](p2p::frost_message_ptr){ return true;});
        ~OnChainService() override {};

        void AddPeer(xonly_pubkey&& pk, string&& addr);

        const ZmqService::peers_map& GetPeersMap() const;

        const std::function<void(p2p::frost_message_ptr)>& GetMessageHandler();

        void Publish(frost_message_ptr m,
                     std::function<void(const xonly_pubkey&, frost_message_ptr)> on_send,
                     std::function<void(const xonly_pubkey&, frost_message_ptr)> on_error) override;

        void Send(const xonly_pubkey& pk, p2p::frost_message_ptr m,
                  std::function<void()> on_error) override;

        void Connect(const xonly_pubkey&, std::function<void(p2p::frost_message_ptr)>) override;

        void WaitForConfirmations();

        ZmqService::Ptr getZmq() const;
    private:
        ZmqService::Ptr m_zmq;
        l15::core::WalletApi m_wallet;
    };

} // namespace l15::p2p
