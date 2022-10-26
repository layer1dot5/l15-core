#pragma once
#include <string>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <semaphore>

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
    typedef std::tuple<std::string, zmq::socket_t, std::list<p2p::frost_message_ptr>, std::unique_ptr<std::mutex>> peer_state;
    typedef std::unordered_map<xonly_pubkey, peer_state, l15::hash<xonly_pubkey>> peers_map;
private:
    peers_map m_peers;
    std::shared_mutex m_peers_mutex;

    const secp256k1_context_struct *m_ctx;
    std::shared_ptr<service::GenericService> mTaskService;

    std::string m_server_addr;

    std::binary_semaphore m_exit_sem;

private:
    static inline std::string& peer_address(peer_state& state) { return get<0>(state); }
    static inline zmq::socket_t& peer_socket(peer_state& state) { return get<1>(state); }
    static inline std::list<p2p::frost_message_ptr>& peer_message_queue(peer_state& state) { return get<2>(state); }
    static inline std::mutex& peer_mutex(peer_state& state) { return *get<3>(state); }



    void ListenCycle(p2p::frost_link_handler&& h);
    void CheckPeers();

    void SendInternal(peer_state& peer, const p2p::FrostMessage &m);

public:
    explicit ZmqService(const secp256k1_context_struct *ctx, std::shared_ptr<service::GenericService> srv)
    : m_peers(), m_ctx(ctx), mTaskService(move(srv)), m_exit_sem(0) {}

    ~ZmqService();

    void AddPeer(xonly_pubkey&& pk, string&& addr)
    { m_peers.emplace(move(pk), peer_state(move(addr), zmq::socket_t(zmq_ctx.value(), zmq::socket_type::push), std::list<p2p::frost_message_ptr>(), std::make_unique<std::mutex>())); }

    void SetSelfPubKey(const xonly_pubkey& pk)
    { m_peers.erase(pk); }

    const peers_map& GetPeersMap() const
    { return m_peers; }

    void StartService(const std::string& addr, p2p::frost_link_handler&& h);

    void Publish(const p2p::FrostMessage& m);
    void Send(const xonly_pubkey& pk, const p2p::FrostMessage& m);
};


}
