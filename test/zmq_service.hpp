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
    xonly_pubkey m_pk;
    std::list<p2p::frost_message_ptr> m_queue;
    p2p::FROST_MESSAGE m_next_phase;
    std::chrono::time_point<std::chrono::steady_clock> m_last_to_confirm_time;
    std::unique_ptr<std::mutex> m_queue_mutex;
public:
    explicit FrostMessagePipeLine(xonly_pubkey&& pk) :
        m_pk(move(pk)),
        m_queue(),
        m_next_phase(p2p::FROST_MESSAGE::NONCE_COMMITMENTS),
        m_last_to_confirm_time(std::chrono::steady_clock::now()),
        m_queue_mutex(std::make_unique<std::mutex>())
        {}
    FrostMessagePipeLine(FrostMessagePipeLine&&) noexcept = default;

    const xonly_pubkey& Pubkey() const
    { return m_pk; }

    void PushMessage(p2p::frost_message_ptr msg);
    p2p::frost_message_ptr PeekNextMessage();
    p2p::frost_message_ptr PeekUnconfirmedMessage(std::chrono::milliseconds confirmation_timeout, size_t& unconfirmed_count);
    void PopCurrentMessage();
    p2p::FROST_MESSAGE GetCurPhase() const
    {
        p2p::FROST_MESSAGE cur_phase = m_next_phase;
        if (cur_phase == p2p::FROST_MESSAGE::NONCE_COMMITMENTS)
            cur_phase = p2p::FROST_MESSAGE::MESSAGE_ID_COUNT;
        else
            cur_phase = static_cast<p2p::FROST_MESSAGE>(static_cast<uint16_t>(m_next_phase) - 1);
        return cur_phase;
    }
    void ConfirmPhase(p2p::FROST_MESSAGE confirm_phase);
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
    > peer;

    typedef std::shared_ptr<peer> peer_state;
    typedef std::unordered_map<xonly_pubkey, peer_state, l15::hash<xonly_pubkey>> peers_map;
private:
    const static std::string STOP;

    const secp256k1_context_struct *m_ctx;
    std::optional<zmq::context_t> zmq_ctx;
    const xonly_pubkey m_pk;
    const p2p::FROST_MESSAGE m_end_phase;
    peers_map m_peers;
    std::shared_mutex m_peers_mutex;

    std::shared_ptr<service::GenericService> mTaskService;

    std::string m_server_addr;

    std::mutex m_protocol_confirmation_mutex;
    std::binary_semaphore m_exit_sem;

    bool m_debug_traces;

private:
    static inline std::string& peer_address(peer_state& state) { return get<0>(*state); }
    static inline zmq::socket_t& peer_socket(peer_state& state) { return get<1>(*state); }
    static inline FrostMessagePipeLine& peer_outgoing_pipeline(peer_state& state) { return get<2>(*state); }
    static inline std::mutex& peer_outgoing_mutex(peer_state& state) { return *get<3>(*state); }
    static inline FrostMessagePipeLine& peer_incoming_pipeline(peer_state& state) { return get<4>(*state); }
    static inline std::mutex& peer_incoming_mutex(peer_state& state) { return *get<5>(*state); }

    void ListenCycle(p2p::frost_link_handler h);
    void CheckPeers();

    void SendInternal(ZmqService::peer_state peer, p2p::frost_message_ptr m);

    void ProcessIncomingPipeline(peer_state peer, p2p::frost_link_handler h);
    void ProcessOutgoingPipeline(peer_state peer);
    void SendWithPipeline(peer_state peer, p2p::frost_message_ptr m);

public:
    explicit ZmqService(const secp256k1_context_struct *ctx, std::shared_ptr<service::GenericService> srv, xonly_pubkey pk, p2p::FROST_MESSAGE end_phase, bool debug_traces)
    : m_ctx(ctx), zmq_ctx(zmq::context_t(10, 1005)), m_pk(move(pk)), m_end_phase(end_phase), m_peers(), mTaskService(move(srv)), m_protocol_confirmation_mutex(), m_exit_sem(0), m_debug_traces(debug_traces) {}

    ~ZmqService();

    void AddPeer(xonly_pubkey&& pk, string&& addr)
    {
        xonly_pubkey pk1(pk), pk2(pk);
        m_peers.emplace(move(pk), std::make_shared<peer>(
            move(addr), zmq::socket_t(zmq_ctx.value(), zmq::socket_type::push),
            FrostMessagePipeLine(move(pk1)), std::make_unique<std::mutex>(),
            FrostMessagePipeLine((move(pk2))), std::make_unique<std::mutex>()
        ));
    }

    const peers_map& GetPeersMap() const
    { return m_peers; }

    void StartService(const std::string& addr, p2p::frost_link_handler&& h);

    void Publish(p2p::frost_message_ptr m);
    void Send(const xonly_pubkey& pk, p2p::frost_message_ptr m);

    void WaitForConfirmations();
};


}
