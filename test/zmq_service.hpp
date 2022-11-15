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

class FrostMessagePipeLine {
    std::list<p2p::frost_message_ptr> m_queue;
    p2p::FROST_MESSAGE m_last_phase;
    std::unique_ptr<std::shared_mutex> m_queue_mutex;
public:
    FrostMessagePipeLine() : m_queue(), m_last_phase(p2p::FROST_MESSAGE::KEY_COMMITMENT), m_queue_mutex(std::make_unique<std::shared_mutex>()) {}
    FrostMessagePipeLine(FrostMessagePipeLine&&) noexcept = default;
    void PushMessage(p2p::frost_message_ptr msg);
    p2p::frost_message_ptr PeekCurrentMessage();
    void PopCurrentMessage();
};

class ZmqService// : public service::ZmqContextSingleton
{
public:
    typedef std::tuple<std::string,
                        zmq::socket_t,
                        FrostMessagePipeLine,        // Outgoing message pipeline
                        std::unique_ptr<std::mutex>, // This mutex is used to guarantee that a peer related message send happens from single thread only
                        FrostMessagePipeLine,        // Incoming message pipeline
                        std::unique_ptr<std::mutex>  // This mutex is used to guarantee that a peer related message receive happens from single thread only
                        > peer_state;
    typedef std::unordered_map<xonly_pubkey, peer_state, l15::hash<xonly_pubkey>> peers_map;
private:
    const static std::string STOP;

    std::optional<zmq::context_t> zmq_ctx;
    peers_map m_peers;
    std::shared_mutex m_peers_mutex;

    const secp256k1_context_struct *m_ctx;
    std::shared_ptr<service::GenericService> mTaskService;

    std::string m_server_addr;

    std::binary_semaphore m_exit_sem;

private:
    static inline std::string& peer_address(peer_state& state) { return get<0>(state); }
    static inline zmq::socket_t& peer_socket(peer_state& state) { return get<1>(state); }
    static inline FrostMessagePipeLine& peer_outgoing_pipeline(peer_state& state) { return get<2>(state); }
    static inline std::mutex& peer_outgoing_mutex(peer_state& state) { return *get<3>(state); }
    static inline FrostMessagePipeLine& peer_incoming_pipeline(peer_state& state) { return get<4>(state); }
    static inline std::mutex& peer_incoming_mutex(peer_state& state) { return *get<5>(state); }

    void ListenCycle(p2p::frost_link_handler h);
    void CheckPeers();

    void ProcessIncomingPipeline(peer_state& peer, p2p::frost_link_handler h);
    void ProcessOutgoingPipeline(peer_state& peer);
    void SendInternal(peer_state& peer, p2p::frost_message_ptr m);

public:
    explicit ZmqService(const secp256k1_context_struct *ctx, std::shared_ptr<service::GenericService> srv)
    : zmq_ctx(zmq::context_t(10, 1005)), m_peers(), m_ctx(ctx), mTaskService(move(srv)), m_exit_sem(0) {}

    ~ZmqService();

    void AddPeer(xonly_pubkey&& pk, string&& addr)
    {
        m_peers.emplace(move(pk), peer_state {
            move(addr), zmq::socket_t(zmq_ctx.value(), zmq::socket_type::push),
            FrostMessagePipeLine(), std::make_unique<std::mutex>(),
            FrostMessagePipeLine(), std::make_unique<std::mutex>()
        });
    }

    void SetSelfPubKey(const xonly_pubkey& pk)
    { m_peers.erase(pk); }

    const peers_map& GetPeersMap() const
    { return m_peers; }

    void StartService(const std::string& addr, p2p::frost_link_handler&& h);

    void Publish(p2p::frost_message_ptr m);
    void Send(const xonly_pubkey& pk, p2p::frost_message_ptr m);
};


}
