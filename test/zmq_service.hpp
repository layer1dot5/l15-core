#pragma once
#include <string>
#include <memory>
#include <unordered_map>
#include <mutex>

#include "common.hpp"
#include "zmq_context.hpp"
#include "p2p_frost.hpp"

namespace l15 {

namespace service {
    class GenericService;
}

class ZmqService : public service::ZmqContextSingleton
{
public:
    typedef std::tuple<std::string, zmq::socket_t, p2p::frost_message_ptr, std::unique_ptr<std::mutex>> peer_state;
    typedef std::unordered_map<xonly_pubkey, peer_state, l15::hash<xonly_pubkey>> peers_map;
private:
    peers_map m_peers;
    std::shared_mutex m_peers_mutex;

    const secp256k1_context_struct *m_ctx;
    std::shared_ptr<service::GenericService> mTaskService;
    zmq::socket_t m_server_sock;

    std::string m_server_addr;

private:

    void ListenCycle(p2p::frost_link_handler&& h);
    void CheckPeer(peers_map::value_type& peer);

    void SendInternal(peer_state& peer, const p2p::FrostMessage &m);

public:
    explicit ZmqService(const secp256k1_context_struct *ctx, std::shared_ptr<service::GenericService> srv)
    : m_peers(), m_ctx(ctx), mTaskService(move(srv)), m_server_sock(zmq_ctx.value(), ZMQ_REP) {}

    ~ZmqService();

    void AddPeer(xonly_pubkey&& pk, string&& addr)
    { m_peers.emplace(move(pk), peer_state(move(addr), zmq::socket_t(zmq_ctx.value(), ZMQ_REQ), p2p::frost_message_ptr(), std::make_unique<std::mutex>())); }

    const peers_map& GetPeersMap() const
    { return m_peers; }

    void StartService(const std::string& addr, p2p::frost_link_handler&& h);

    void Publish(const p2p::FrostMessage& m);
    void Send(const xonly_pubkey& pk, const p2p::FrostMessage& m);
};


}
