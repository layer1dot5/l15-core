#pragma once
#include <string>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <semaphore>

#include <tbb/concurrent_vector.h>
#include <boost/container/flat_map.hpp>

#include "common.hpp"
#include "zmq_context.hpp"
#include "p2p_frost.hpp"

namespace l15 {

namespace service {
    class GenericService;
}

typedef std::function<void(p2p::frost_message_ptr)> frost_link_handler;

class ZmqService : public p2p::P2PInterface<xonly_pubkey, p2p::FrostMessage>
{
public:
    typedef std::shared_ptr<ZmqService> Ptr;
    typedef std::tuple<std::string, zmq::socket_t> peer;
    typedef std::shared_ptr<peer> peer_state;
    typedef std::unordered_map<xonly_pubkey, peer_state, l15::hash<xonly_pubkey>> peers_map;
private:
    const static std::string STOP;

    const secp256k1_context_struct *m_ctx;
    std::optional<zmq::context_t> zmq_ctx;
    peers_map m_peers;
    std::shared_mutex m_peers_mutex;

    std::shared_ptr<service::GenericService> mTaskService;

    xonly_pubkey m_self_address;
    std::string m_server_address;

    std::mutex m_protocol_confirmation_mutex;
    std::shared_mutex m_exit_mutex;

    std::function<bool(p2p::frost_message_ptr)> m_message_filter;
    std::function<void(p2p::frost_message_ptr)> m_subscription_handler;

private:
    static inline const std::string& peer_address(const peer_state& state) { return get<0>(*state); }
    static inline zmq::socket_t& peer_socket(const peer_state& state) { return get<1>(*state); }

    void ListenCycle(std::string server_addr, frost_link_handler h);
    void CheckPeers();

    void SendInternal(const ZmqService::peers_map::value_type&, p2p::frost_message_ptr m);

public:
    explicit ZmqService(const secp256k1_context_struct *ctx, std::shared_ptr<service::GenericService> srv, std::function<bool(p2p::frost_message_ptr)> msg_filter = [](p2p::frost_message_ptr){ return true;})
    : m_ctx(ctx), zmq_ctx(zmq::context_t(10)), m_peers(), mTaskService(move(srv)), m_protocol_confirmation_mutex(), m_exit_mutex(), m_message_filter(move(msg_filter)) {}

    ~ZmqService() override;

    void AddPeer(xonly_pubkey&& pk, string&& addr)
    {
        xonly_pubkey pk1(pk), pk2(pk);
        m_peers.emplace(move(pk), std::make_shared<peer>(
            move(addr), zmq::socket_t(zmq_ctx.value(), zmq::socket_type::client)
        ));
    }

    const peers_map& GetPeersMap() const
    { return m_peers; }

    const std::function<void(p2p::frost_message_ptr)>& GetMessageHandler()
    { return m_subscription_handler; }

    void Publish(p2p::frost_message_ptr m,
                 std::function<void(const xonly_pubkey&, p2p::frost_message_ptr)> on_send,
                 std::function<void(const xonly_pubkey&, p2p::frost_message_ptr)> on_error) override;

    void Send(const xonly_pubkey& pk, p2p::frost_message_ptr m,
              std::function<void()> on_error) override;

    void Connect(const xonly_pubkey&, std::function<void(p2p::frost_message_ptr)>) override;

    void WaitForConfirmations();
};

}
