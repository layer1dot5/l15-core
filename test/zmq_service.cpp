
#include <deque>
#include <stdexcept>
#include <functional>

#include "wrapstream.hpp"

#include "generic_service.hpp"
#include "zmq_service.hpp"

namespace l15 {

const std::string ZmqService::STOP("stop");

ZmqService::~ZmqService()
{
    if (!m_server_addr.empty()) {
        zmq::socket_t sock(zmq_ctx.value(), zmq::socket_type::push);
        zmq::message_t stop(STOP);

        std::string local_addr = m_server_addr.replace(m_server_addr.find('*'), 1, "localhost");

        sock.connect(local_addr);
        sock.send(stop, zmq::send_flags::none);
        m_exit_sem.acquire();
        sock.close();

        //std::binary_semaphore peers_sem(0);
        mTaskService->Serve([this]() {
            std::shared_lock lock(m_peers_mutex);
            for (auto &peer: m_peers) {
                peer_socket(peer.second).close();
            }
            //peers_sem.release();
        });
        //peers_sem.acquire();

        std::unique_lock lock(m_peers_mutex);
        m_peers.clear();
    }

    if (zmq_ctx.has_value()) {
        zmq_ctx->shutdown();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void ZmqService::StartService(const std::string& addr, p2p::frost_link_handler&& h)
{
    m_server_addr = addr;

    //mTaskService->Serve([this]() {
        for (auto &peer: m_peers) {
            peer_socket(peer.second).connect(peer_address(peer.second));
        }
    //});

    std::thread(&ZmqService::ListenCycle, this, move(h)).detach();
}

void ZmqService::Publish(p2p::frost_message_ptr m)
{
    std::shared_lock lock(m_peers_mutex);
    for (auto& peer_data: m_peers) {
        SendInternal(peer_data.second, m);
    }
}

void ZmqService::Send(const xonly_pubkey &pk, p2p::frost_message_ptr m)
{
    std::shared_lock lock(m_peers_mutex);
    auto peer_it = m_peers.find(pk);
    if (peer_it == m_peers.end()) {
        throw std::invalid_argument(hex(pk));
    }
    lock.unlock();

    SendInternal(peer_it->second, move(m));
}

void ZmqService::ProcessIncomingPipeline(ZmqService::peer_state peer, p2p::frost_link_handler h)
{
    std::unique_lock lock(peer_incoming_mutex(peer), std::try_to_lock);
    if (lock.owns_lock()) {
        p2p::frost_message_ptr msg;
        while((msg = peer_incoming_pipeline(peer).PeekCurrentMessage())) {
            try {
                h(move(msg));
                peer_incoming_pipeline(peer).PopCurrentMessage();
            }
            catch (Error &e) {
                std::cerr << "Cannot process FROST message: " << e.what() << ": " << e.details() << std::endl;
            }
            catch (std::exception &e) {
                std::cerr << "Cannot process FROST message: " << e.what() << std::endl;
            }
            catch (...) {
                std::cerr << "Cannot process FROST message: unknown error" << std::endl;
            }
        }
    }
}

void ZmqService::ProcessOutgoingPipeline(ZmqService::peer_state peer)
{
    std::unique_lock lock(peer_outgoing_mutex(peer), std::try_to_lock);
    if (lock.owns_lock()) {
        p2p::frost_message_ptr msg;
        while((msg = peer_outgoing_pipeline(peer).PeekCurrentMessage())) {

            cex::stream<std::deque<uint8_t>> data;
            p2p::Serialize(data, m_ctx, *msg);

            std::clog << "Sending " << data.size() <<" bytes:\n" << hex(data) << std::endl;

            try {
                zmq::message_t zmq_msg(data.begin(), data.end());

                auto res = peer_socket(peer).send(move(zmq_msg), zmq::send_flags::dontwait);
                if (!res) {
                    throw std::runtime_error("send returned zero bytes sent");
                }

                if (res.value() < data.size()) {
                    throw std::runtime_error((std::ostringstream() << "just part of message has been sent: " << res.value() << " of " << data.size()).str());
                }

                peer_outgoing_pipeline(peer).PopCurrentMessage();
            }
            catch (Error &e) {
                std::cerr << "Send error: " << e.what() << ": " << e.details() << std::endl;
            }
            catch (std::exception &e) {
                std::cerr << "Send error: " << e.what() << std::endl;
            }
            catch (...) {
                std::cerr << "Send error: unknown error" << std::endl;
            }
        }
    }
}

void ZmqService::SendInternal(ZmqService::peer_state peer, p2p::frost_message_ptr m)
{
    peer_outgoing_pipeline(peer).PushMessage(move(m));
    mTaskService->Serve([this, peer]()
    {
        ProcessOutgoingPipeline(peer);
    });
}

void ZmqService::ListenCycle(p2p::frost_link_handler h)
{
    cex::stream<std::deque<std::uint8_t>> buffer;

    zmq::socket_t server_sock(zmq_ctx.value(), zmq::socket_type::pull);

    server_sock.bind(m_server_addr);

    std::clog << "Listening at: " << m_server_addr << std::endl;

    for(bool next_block = false;;) {
        try {

            if (!next_block && !buffer.empty()) {
                try {
                    p2p::frost_message_ptr msg = p2p::Unserialize(m_ctx, buffer);
                    buffer.clear();

                    std::shared_lock lock(m_peers_mutex);
                    peers_map::iterator peer_it = m_peers.find(msg->pubkey);
                    if (peer_it == m_peers.end()) {
                        throw p2p::WrongMessageData(*msg);
                    }
                    peer_state peer = peer_it->second;
                    lock.unlock();

                    peer_incoming_pipeline(peer).PushMessage(move(msg));
                    mTaskService->Serve([this, p = move(peer), h]() { ProcessIncomingPipeline(p, h); });
                }
                catch(p2p::UnserializeError& e) {
                    buffer.clear();
                    std::cerr << (std::ostringstream() << "Skipping: " << e.what() << "\n" << e.details()).str() << std::endl;
                }
                catch(...) {
                    buffer.clear();
                    std::cerr << "Skipping unknown error" << std::endl;
                }
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
                    std::this_thread::sleep_for(std::chrono::milliseconds(10) - elapsed);
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
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        catch (...) {
            std::cerr << "Skipping unknown error" << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    server_sock.close();

    m_exit_sem.release();
}


void ZmqService::CheckPeers()
{
    std::for_each(m_peers.begin(), m_peers.end(), [this](auto & peer) {
        ProcessOutgoingPipeline(peer.second);
    });
}

void FrostMessagePipeLine::PushMessage(p2p::frost_message_ptr msg)
{
    std::lock_guard lock(*m_queue_mutex);
    auto ins_it = std::find_if(m_queue.begin(), m_queue.end(), [msg](const p2p::frost_message_ptr& que_msg){ return que_msg->id > msg->id; });
    m_queue.insert(ins_it, move(msg));
}

p2p::frost_message_ptr FrostMessagePipeLine::PeekCurrentMessage()
{
    std::lock_guard lock(*m_queue_mutex);
    return (!m_queue.empty() && (m_queue.front()->id <= m_last_phase)) ? m_queue.front() : l15::p2p::frost_message_ptr();
}

void FrostMessagePipeLine::PopCurrentMessage()
{
    std::lock_guard lock(*m_queue_mutex);
    if (!m_queue.empty()) {
        if (m_last_phase == m_queue.front()->id)
            m_last_phase = static_cast<p2p::FROST_MESSAGE>(static_cast<uint16_t>(m_last_phase) + 1);
        m_queue.pop_front();
    }
}


}
