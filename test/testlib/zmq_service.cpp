
#include <deque>
#include <stdexcept>
#include <functional>
#include <stdexcept>
#include <sstream>

#include "wrapstream.hpp"

#include "generic_service.hpp"
#include "zmq_service.hpp"

namespace l15 {

const std::string ZmqService::STOP("stop");

ZmqService::~ZmqService()
{
    std::clog << "Destroying ZMQ service" << std::endl;

    zmq::socket_t sock(zmq_ctx.value(), zmq::socket_type::client);
    zmq::message_t stop(STOP);

    std::string local_addr = m_server_address;
    local_addr.replace(local_addr.find('*'), 1, "localhost");

    sock.connect(local_addr);
    sock.send(stop, zmq::send_flags::none);
    sock.close();

//        mTaskService->Serve([this]() {
//            std::shared_lock lock(m_peers_mutex);
    for (auto &peer: m_peers) {
        peer_socket(peer.second).close();
    }
//        });

    std::unique_lock lock(m_peers_mutex);
    m_peers.clear();

    std::unique_lock exit_lock(m_exit_mutex);

    if (zmq_ctx.has_value()) {
        zmq_ctx->shutdown();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void ZmqService::Connect(const xonly_pubkey& local_pk, std::function<void(p2p::frost_message_ptr)> h)
{
    if (!m_server_address.empty()) {
        throw std::runtime_error("already subscribed");
    }

    auto peer_it = m_peers.find(local_pk);
    if (peer_it != m_peers.end()) {

        const std::string self_address = peer_address(peer_it->second);

        size_t p1 = self_address.find("//");
        if (p1 == std::string::npos) {
            p2p::WrongAddress(std::string(self_address));
        }
        size_t p2 = self_address.find(":", p1+2);
        if (p2 == std::string::npos) {
            p2p::WrongAddress(std::string(self_address));
        }
        std::string listen_addr = self_address.substr(0, p1+2) + "*" + self_address.substr(p2);

        m_self_address = local_pk;
        m_server_address = listen_addr;
        m_subscription_handler = h;

        std::thread(&ZmqService::ListenCycle, this, move(listen_addr),
                    [this, message_handler = move(h)] (p2p::frost_message_ptr m) {
                        if (m_message_filter(m))
                            message_handler(m);
                    }
        ).detach();
    }
    else {
        throw p2p::UnknownPeer(hex(local_pk));
    }

    for (auto peer: m_peers) {
        if (peer.first != local_pk) {
            peer_socket(peer.second).connect(peer_address(peer.second));
        }
    }
}

void ZmqService::Publish(p2p::frost_message_ptr m,
                         std::function<void(const xonly_pubkey&, p2p::frost_message_ptr)> on_send,
                         std::function<void(const xonly_pubkey&, p2p::frost_message_ptr)> on_error)
{
    std::shared_lock lock(m_peers_mutex);
    for (auto &peer: m_peers) {
        if (peer.first == m_self_address)
            continue;

        auto peer_msg = m->Copy();
        mTaskService->Serve([=, this]() {
            try {
                on_send(peer.first, peer_msg);
                SendInternal(peer, peer_msg);
            } catch(...) {
                on_error(peer.first, peer_msg);
            }
        });
    }
}

void ZmqService::Send(const xonly_pubkey &pk, p2p::frost_message_ptr m,
                      std::function<void()> on_error)
{
    if (pk == m_self_address)
        throw std::runtime_error("send to self");

    std::shared_lock lock(m_peers_mutex);
    auto peer_it = m_peers.find(pk);
    if (peer_it == m_peers.end()) {
        throw p2p::UnknownPeer(hex(pk));
    }

    mTaskService->Serve([this, peer = *peer_it, m = move(m), on_error]() {
        try {
            SendInternal(peer, m);
        } catch(...) {
            on_error();
        }
    });
}

void ZmqService::SendInternal(const ZmqService::peers_map::value_type& peer, p2p::frost_message_ptr msg)
{
    std::clog << (std::ostringstream() << ">>> " << msg->ToString() << "\n").str() << std::flush;

    cex::stream<std::deque<uint8_t>> data;
    if (msg) {
        p2p::Serialize(data, m_ctx, *msg);
    }

    zmq::message_t zmq_msg(data.begin(), data.end());

    auto res = peer_socket(peer.second).send(move(zmq_msg), zmq::send_flags::dontwait);
    if (!res) {
        throw p2p::SendError(hex(peer.first));
    }

    if (res.value() < data.size()) {
        throw std::runtime_error((std::ostringstream() << "just part of message has been sent: " << res.value() << " of " << data.size()).str());
    }
}


void ZmqService::CheckPeers()
{
//    mTaskService->Serve([this]() {
//
//        //std::clog << "^^^^ End phase: " << static_cast<uint16_t>(m_end_phase) << std::endl;
//
//        size_t confirmation_wait_count = 0;
//        std::for_each(m_peers.begin(), m_peers.end(), [this, &confirmation_wait_count](auto & peer) {
//            try {
//                m_protocol_confirmation_mutex.try_lock();
//                std::unique_lock lock(peer_outgoing_mutex(peer.second), std::try_to_lock);
//                p2p::frost_message_ptr out_msg;
//                if (lock.owns_lock()) {
//                    size_t unconfirmed_out_count = 0;
//                    out_msg = peer_outgoing_pipeline(peer.second).PeekUnconfirmedMessage(std::chrono::seconds(7), unconfirmed_out_count);
//                    confirmation_wait_count += unconfirmed_out_count;
//                    if (out_msg) {
//                        std::clog << (std::ostringstream() << "Repeat sending to " << hex(peer.first).substr(0, 8)).str() << std::endl;
//                        SendInternal(peer.second, out_msg);
//                    }
//                    else {
//                        size_t unconfirmed_in_count = 0;
//                        p2p::frost_message_ptr in_msg = peer_incoming_pipeline(peer.second).PeekUnconfirmedMessage(std::chrono::seconds(7), unconfirmed_in_count);
//                        confirmation_wait_count += unconfirmed_in_count;
//
//                    }
//                }
//            }
//            catch (Error &e) {
//                std::cerr << "Send error: " << e.what() << ": " << e.details() << std::endl;
//            }
//            catch (std::exception &e) {
//                std::cerr << "Send error: " << e.what() << std::endl;
//            }
//            catch (...) {
//                std::cerr << "Send error: unknown error" << std::endl;
//            }
//        });
//
//        //std::clog << "^^^^ Confirmation wait count: " << confirmation_wait_count << std::endl;
//
//
//        if (confirmation_wait_count == 0) {
//            m_protocol_confirmation_mutex.unlock();
//        }
//    });
}


void ZmqService::ListenCycle(const std::string server_addr, frost_link_handler h)
{
    std::shared_lock thread_lock(m_exit_mutex);

    cex::stream<std::deque<uint8_t>> buffer;

    zmq::socket_t server_sock(zmq_ctx.value(), zmq::socket_type::server);

    server_sock.bind(server_addr);

    std::clog << "Listening at: " << server_addr << std::endl;

    for(bool next_block = false;;) {
        try {

            if (!next_block && !buffer.empty()) {
                try {
                    p2p::frost_message_ptr msg = nullptr;
                    msg = p2p::Unserialize(m_ctx, buffer);

                    buffer.clear();

                    std::shared_lock lock(m_peers_mutex);
                    auto peer_it = m_peers.find(msg->pubkey);
                    if (peer_it == m_peers.end()) {
                        throw p2p::WrongMessageData(*msg);
                    }
                    peer_state peer = peer_it->second;
                    lock.unlock();

                    //std::clog << (std::ostringstream() << "vvv " << msg->ToString()).str() << std::endl;
                    mTaskService->Serve([this, m = move(msg), h]() {
                        std::clog << (std::ostringstream() << "[" << hex(m_self_address).substr(0,8) << "] <<< " << m->ToString() << "\n").str() << std::flush;
                        h(m);
                        std::clog << (std::ostringstream() << "[" << hex(m_self_address).substr(0,8) << "] ||| " << m->ToString() << "\n").str() << std::flush;
                    });
                }
                catch(...) {
                    buffer.clear();
                    print_error(std::cerr);
                }
            }

            zmq::message_t m;

            auto cycle_start = std::chrono::steady_clock::now();

            auto res = server_sock.recv(m, zmq::recv_flags::dontwait);
            next_block = m.more();

            if (!res) {

//                std::clog << "No message" << std::endl;
//
//                CheckPeers();

                auto cycle_end = std::chrono::steady_clock::now();
                auto elapsed = cycle_end - cycle_start;
                if (elapsed < std::chrono::milliseconds(50)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(50) - elapsed);
                }
            }
            else if (m == zmq::message_t(STOP)) {
                break;
            }
            else {
                //std::clog << (std::ostringstream() << "P2P message size: " << m.size() << ", next_block: " << next_block).str() << std::endl;

                buffer.append(m.data<uint8_t>(), m.data<uint8_t>() + m.size());
            }
        }
        catch (...) {
            std::cerr << "Skipping unknown error" << std::endl;
            print_error(std::cerr);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    server_sock.close();
    std::clog << "Stop listening at: " << server_addr << std::endl;
}

void ZmqService::WaitForConfirmations()
{
//    std::lock_guard lock(m_protocol_confirmation_mutex);
}

}
