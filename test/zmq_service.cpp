
#include <deque>
#include <stdexcept>
#include <functional>

#include "wrapstream.hpp"

#include "generic_service.hpp"
#include "zmq_service.hpp"
#include "p2p_frost.hpp"

namespace l15 {

ZmqService::~ZmqService()
{
    if (!m_server_addr.empty()) {
        zmq::socket_t sock(zmq_ctx.value(), ZMQ_REQ);
        zmq::message_t stop(STOP);

        sock.connect(m_server_addr);
        sock.send(stop);
    }
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

    if (get<2>(peer_it->second)) {
        throw std::logic_error("Peer message queue is not empty");
    }

    SendInternal(peer_it->second, m);
}

void ZmqService::SendInternal(ZmqService::peer_state &peer, const p2p::FrostMessage &m)
{
    cex::stream<std::deque<uint8_t>> buf;
    p2p::Serialize<cex::stream<std::deque<uint8_t>>>(buf, m_ctx, m);

    mTaskService->Serve([this, &peer](cex::stream<std::deque<uint8_t>>&& data)
    {
        zmq::message_t zmq_msg(data.begin(), data.end());

        if (!get<1>(peer)) {
            get<1>(peer).connect(get<0>(peer));
        }
        if(!get<1>(peer).send(move(zmq_msg), zmq::send_flags::dontwait)) {
            cex::stream<std::deque<uint8_t>> buf;
            auto queued_msg = p2p::Unserialize(m_ctx, buf);

            std::lock_guard lock(*get<3>(peer));
            get<2>(peer) = move(queued_msg); // store message to send later if failed to send now
        }
    }, move(buf));
}

void ZmqService::ListenCycle(p2p::frost_link_handler&& h)
{
    cex::stream<std::deque<std::uint8_t>> buffer;

    m_server_sock.bind(m_server_addr);

    for(bool next_block = false;;) {
        try {

            if (!next_block && !buffer.empty()) {
                p2p::frost_message_ptr msg = p2p::Unserialize(m_ctx, buffer);

                auto peer_it = m_peers.find(msg->pubkey);
                if (peer_it == m_peers.end()) {
                    throw p2p::WrongMessageData(*msg);
                }

                p2p::frost_message_ptr rep_msg;
                {
                    std::lock_guard lock(*get<3>(peer_it->second));
                    if (!get<2>(peer_it->second)) {
                        rep_msg = move(get<2>(peer_it->second));
                    }
                }
                if (rep_msg) {
                    cex::stream <std::deque<uint8_t>> buf;
                    p2p::Serialize < cex::stream < std::deque<uint8_t>>>(buf, m_ctx, *rep_msg);
                    zmq::message_t zmq_rep_msg(buf.begin(), buf.end());
                    if (!m_server_sock.send(move(zmq_rep_msg), zmq::send_flags::dontwait)) {
                        std::lock_guard lock(*get<3>(peer_it->second));
                        get<2>(peer_it->second) = move(rep_msg); // place message back if failed to send
                    }
                }

                h(*msg);
            }

            zmq::message_t m;

            auto cycle_start = std::chrono::steady_clock::now();

            auto res = m_server_sock.recv(m, zmq::recv_flags::dontwait);

            if (!res) {
                std::for_each(m_peers.begin(), m_peers.end(), std::bind(&ZmqService::CheckPeer, this, std::placeholders::_1));

                auto cycle_end = std::chrono::steady_clock::now();
                auto elapsed = cycle_end - cycle_start;
                if (elapsed < std::chrono::milliseconds(100)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500) - elapsed);
                }

            }
            else if (m == zmq::message_t(STOP)) {
                break;
            }
            else {
                buffer.append(m.data<uint8_t>(), m.data<uint8_t>() + m.size());
            }

            next_block = m.more();
        }
        catch (std::exception& e) {
            std::cerr << "Skipping unknown error: " << e.what() << std::endl;
        }
        catch (...) {
            std::cerr << "Skipping unknown error" << std::endl;
        }
    }
}


void ZmqService::CheckPeer(peers_map::value_type& peer)
{
        p2p::frost_message_ptr rep_msg;
        {
            std::lock_guard lock(*get<3>(peer.second));
            if (!get<2>(peer.second)) {
                rep_msg = move(get<2>(peer.second));
            }
        }
        if (rep_msg) {
            cex::stream<std::deque<uint8_t>> buf;
            p2p::Serialize<cex::stream<std::deque<uint8_t>>>(buf, m_ctx, *rep_msg);
            zmq::message_t zmq_rep_msg(buf.begin(), buf.end());
            if (!m_server_sock.send(move(zmq_rep_msg), zmq::send_flags::dontwait)) {
                std::lock_guard lock(*get<3>(peer.second));
                get<2>(peer.second) = move(rep_msg); // place message back if failed to send
            }
        }
}


}
