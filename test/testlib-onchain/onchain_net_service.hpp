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
#include "config.hpp"
#include "channel_keys.hpp"
#include "onchain_service.hpp"

namespace l15::p2p {

    template <class D>
    struct ChainTracer {
        size_t& counter;

        void operator()(const D& data)
        {
            ++counter;
            //std::clog << "Chain trace: " << data.ToString() << std::endl;
        }
    };

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
        typedef std::shared_ptr<AbstractOnChainWriter> Ptr;
    public:
        AbstractOnChainWriter() = default;
        virtual ~AbstractOnChainWriter() = default;

        virtual void Write(const std::string &payload) = 0;
        virtual const string &getAddress() const = 0;
    };

    class OnChainWriterV1: public AbstractOnChainWriter {
    public:
        OnChainWriterV1(const l15::Config &config, const std::string &walletName);
        OnChainWriterV1& operator<<(const std::string &payload);

        void generateBlocks(const std::string &amount); // TODO Needed only for tests. Remove?

        size_t getBlockCnt() const;
        size_t getTxCnt() const;

        // AbstractOnChainWriter interface
        void Write(const std::string &payload) override;
        const string &getAddress() const override;

    protected:
        std::optional<l15::core::Utxo> findGoodUtxo(CAmount minSatoshi);

    private:

        core::WalletApi m_wallet;
        l15::core::ChannelKeys m_outKey;

        l15::core::ChannelKeys m_key;

        onchain_service::OnChainService m_onChainService;
        size_t m_blockCnt = 0;
        size_t m_txCnt = 0;
        std::string m_address;
        std::string m_walletName;
        std::string m_walletAddress;
    public:

    };

    class AbstractOnChainReader {
    public:
        AbstractOnChainReader() = default;
        virtual ~AbstractOnChainReader() = default;

        virtual void Read() = 0;
    };

    class OnChainService: public P2PInterface<xonly_pubkey, p2p::FrostMessage>  {
    public:
        explicit OnChainService(const AbstractOnChainWriter::Ptr &writer,
                                const secp256k1_context_struct *ctx,
                                std::shared_ptr<service::GenericService> srv,
                                std::function<bool(p2p::frost_message_ptr)> msg_filter = [](p2p::frost_message_ptr){ return true;});
        //~OnChainService() override {};

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
        AbstractOnChainWriter::Ptr m_writer;


    };

} // namespace l15::p2p
