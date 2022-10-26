
#include <deque>
#include <stdexcept>
#include <functional>

#include "wrapstream.hpp"

#include "generic_service.hpp"
#include "zmq_service.hpp"

namespace l15 {

ZmqService::~ZmqService()
{
    if (!m_server_addr.empty()) {
        zmq::socket_t sock(zmq_ctx.value(), zmq::socket_type::push);
        zmq::message_t stop(STOP);

        std::string local_addr = m_server_addr.replace(m_server_addr.find('*'), 1, "localhost");

        sock.connect(local_addr);
        sock.send(stop, zmq::send_flags::none);
    }
    m_exit_sem.acquire();
}

void ZmqService::StartService(const std::string& addr, p2p::frost_link_handler&& h)
{
    m_server_addr = addr;
    mTaskService->Serve(&ZmqService::ListenCycle, this, move(h));
}

void ZmqService::Publish(const p2p::FrostMessage& m)
{
    for (auto& peer_data: m_peers) {
        SendInternal(peer_data.second, m);
    }
}

void ZmqService::Send(const xonly_pubkey &pk, const p2p::FrostMessage& m)
{
    auto peer_it = m_peers.find(pk);
    if (peer_it == m_peers.end()) {
        throw std::invalid_argument(hex(pk));
    }

    SendInternal(peer_it->second, m);
}

void ZmqService::SendInternal(ZmqService::peer_state &peer, const p2p::FrostMessage &m)
{
    cex::stream<std::deque<uint8_t>> buf;
    p2p::Serialize<cex::stream<std::deque<uint8_t>>>(buf, m_ctx, m);

    mTaskService->Serve([this, &peer](cex::stream<std::deque<uint8_t>>&& data)
    {
        std::lock_guard lock(peer_mutex(peer));
        if (!peer_message_queue(peer).empty()) {

            std::clog << "Queue is not empty. Add to queue to send later" << std::endl;

            p2p::frost_message_ptr queued_msg = p2p::Unserialize(m_ctx, data);
            data.clear();

            peer_message_queue(peer).emplace_back(move(queued_msg)); // store passed message to queue to send later

            // and load first message from queue
            p2p::Serialize<cex::stream<std::deque<uint8_t>>>(data, m_ctx, *peer_message_queue(peer).front());
            peer_message_queue(peer).pop_front();
        }

        try {
            zmq::message_t zmq_msg(data.begin(), data.end());

            //if (!peer_socket(peer)) {
                peer_socket(peer).connect(peer_address(peer));
            //}
            if (!peer_socket(peer).send(move(zmq_msg), zmq::send_flags::dontwait)) {
                throw zmq::error_t();
            }
        }
        catch(zmq::error_t& e)
        {
            std::clog << "Cannot send now. Insert to queue start" << std::endl;

            p2p::frost_message_ptr msg = p2p::Unserialize(m_ctx, data);
            peer_message_queue(peer).emplace_front(move(msg)); // store message to send later if failed to send now
        }
    }, move(buf));
}

void ZmqService::ListenCycle(p2p::frost_link_handler&& h)
{
    cex::stream<std::deque<std::uint8_t>> buffer;

    zmq::socket_t server_sock(zmq_ctx.value(), zmq::socket_type::pull);

    server_sock.bind(m_server_addr);

    std::clog << "Listening at: " << m_server_addr << std::endl;

    for(bool next_block = false;;) {
        try {

            if (!next_block && !buffer.empty()) {
                p2p::frost_message_ptr msg = p2p::Unserialize(m_ctx, buffer);
                buffer.clear();

                auto peer_it = m_peers.find(msg->pubkey);
                if (peer_it == m_peers.end()) {
                    throw p2p::WrongMessageData(*msg);
                }

//                try {
//                    // !!! lock through blocing socket call !!!
//                    std::lock_guard lock(peer_mutex(peer_it->second));
//                    if (!peer_message_queue(peer_it->second).empty()) {
//                        cex::stream<std::deque<uint8_t>> buf;
//                        p2p::Serialize<cex::stream<std::deque<uint8_t>>>(buf, m_ctx, *peer_message_queue(peer_it->second).front());
//                        zmq::message_t zmq_rep_msg(buf.begin(), buf.end());
//                        if (!peer_socket(peer_it->second)) {
//                            peer_socket(peer_it->second).connect(peer_address(peer_it->second));
//                        }
//                        if (peer_socket(peer_it->second).send(move(zmq_rep_msg), zmq::send_flags::dontwait)) {
//                            peer_message_queue(peer_it->second).pop_front();
//                        }
//                    }
//                }
//                catch (...) {
//
//                }

                h(*msg);
            }

            zmq::message_t m;

            auto cycle_start = std::chrono::steady_clock::now();

            auto res = server_sock.recv(m, zmq::recv_flags::dontwait);
            next_block = m.more();

            if (!res) {
                CheckPeers();

                auto cycle_end = std::chrono::steady_clock::now();
                auto elapsed = cycle_end - cycle_start;
                if (elapsed < std::chrono::milliseconds(10)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(50) - elapsed);
                }
            }
            else if (m == zmq::message_t(STOP)) {
                break;
            }
            else {
                buffer.append(m.data<uint8_t>(), m.data<uint8_t>() + m.size());
            }
        }
        catch (std::exception& e) {
            std::cerr << "Skipping unknown error: " << e.what() << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
        catch (...) {
            std::cerr << "Skipping unknown error" << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
    }

    m_exit_sem.release();
}


void ZmqService::CheckPeers()
{
    std::for_each(m_peers.begin(), m_peers.end(), [this](auto & peer) {

        cex::stream<std::deque<uint8_t>> buf;
        try {
            std::unique_lock lock(peer_mutex(peer.second), std::try_to_lock);
            if (!lock || peer_message_queue(peer.second).empty()) {
                return;
            }

            const p2p::FrostMessage& msg = *(peer_message_queue(peer.second).front());

            std::clog << "Process queue. Try to send message: " << msg.id << std::endl;

            p2p::Serialize<cex::stream<std::deque<uint8_t>>>(buf, m_ctx, msg);
            zmq::message_t zmq_msg(buf.begin(), buf.end());

            //if (!peer_socket(peer.second)) {
                peer_socket(peer.second).connect(peer_address(peer.second));
            //}
            if (peer_socket(peer.second).send(move(zmq_msg), zmq::send_flags::dontwait)) {
                peer_message_queue(peer.second).pop_front();
                std::clog << "Peer message sent" << std::endl;
            }
        }
        catch (std::exception& e) {
            std::cerr << "CheckPeers: Skipping unknown error: " << e.what() << std::endl;
        }
        catch (...) {
            std::cerr << "CheckPeers: Skipping unknown error" << std::endl;
        }
    });
}


}
