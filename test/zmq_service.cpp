
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

    for (auto &peer: m_peers) {
        peer_socket(peer.second).connect(peer_address(peer.second));
    }

    std::thread(&ZmqService::ListenCycle, this, move(h)).detach();
}

void ZmqService::Publish(p2p::frost_message_ptr m)
{
    std::shared_lock lock(m_peers_mutex);
    for (auto& peer_data: m_peers) {
        SendWithPipeline(peer_data.second, m);
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

    SendWithPipeline(peer_it->second, move(m));
}

void ZmqService::ProcessIncomingPipeline(ZmqService::peer_state peer, p2p::frost_link_handler h)
{
    try {
        std::unique_lock lock(peer_incoming_mutex(peer), std::try_to_lock);
        if (lock.owns_lock()) {
            p2p::frost_message_ptr msg;
            while ((msg = peer_incoming_pipeline(peer).PeekNextMessage())) {
                h(move(msg));
                peer_incoming_pipeline(peer).PopCurrentMessage();
            }
        }
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


void ZmqService::SendInternal(ZmqService::peer_state peer, p2p::frost_message_ptr msg)
{
    cex::stream<std::deque<uint8_t>> data;
    if (msg) {
        p2p::Serialize(data, m_ctx, *msg);
    }
    else {
        p2p::FrostMessage m(p2p::FROST_MESSAGE::MESSAGE_ID_COUNT, xonly_pubkey(m_pk));
        m.Serialize(data);
    }

    auto cur_phase = peer_incoming_pipeline(peer).GetCurPhase();
    data << cur_phase;

    if (m_debug_traces)
        std::clog << (std::ostringstream() << "Sending to " << hex(peer_outgoing_pipeline(peer).Pubkey()).substr(0, 8) << "... "<< data.size() <<"b:\n" << hex(data)).str() << std::endl;

    zmq::message_t zmq_msg(data.begin(), data.end());

    auto res = peer_socket(peer).send(move(zmq_msg), zmq::send_flags::dontwait);
    if (!res) {
        throw std::runtime_error("send returned zero bytes sent");
    }

    if (res.value() < data.size()) {
        throw std::runtime_error((std::ostringstream() << "just part of message has been sent: " << res.value() << " of " << data.size()).str());
    }

    peer_incoming_pipeline(peer).ConfirmPhase(cur_phase);
}


void ZmqService::ProcessOutgoingPipeline(ZmqService::peer_state peer)
{
    try {
        std::unique_lock lock(peer_outgoing_mutex(peer), std::try_to_lock);
        if (lock.owns_lock()) {
            p2p::frost_message_ptr msg;
            while ((msg = peer_outgoing_pipeline(peer).PeekNextMessage())) {
                SendInternal(peer, msg);
                peer_outgoing_pipeline(peer).PopCurrentMessage();
            }
        }
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


void ZmqService::SendWithPipeline(ZmqService::peer_state peer, p2p::frost_message_ptr m)
{
    m_protocol_confirmation_mutex.try_lock();

    peer_outgoing_pipeline(peer).PushMessage(move(m));
    mTaskService->Serve([this, peer]()
    {
        ProcessOutgoingPipeline(peer);
    });
}


void ZmqService::CheckPeers()
{
    mTaskService->Serve([this]() {

        //std::clog << "^^^^ End phase: " << static_cast<uint16_t>(m_end_phase) << std::endl;

        size_t confirmation_wait_count = 0;
        std::for_each(m_peers.begin(), m_peers.end(), [this, &confirmation_wait_count](auto & peer) {
            try {
                m_protocol_confirmation_mutex.try_lock();
                std::unique_lock lock(peer_outgoing_mutex(peer.second), std::try_to_lock);
                p2p::frost_message_ptr out_msg;
                if (lock.owns_lock()) {
                    size_t unconfirmed_out_count = 0;
                    out_msg = peer_outgoing_pipeline(peer.second).PeekUnconfirmedMessage(std::chrono::seconds(7), unconfirmed_out_count);
                    confirmation_wait_count += unconfirmed_out_count;
                    if (out_msg) {
                        if (m_debug_traces)
                            std::clog << (std::ostringstream() << "Repeat sending to " << hex(peer.first).substr(0, 8)).str() << std::endl;
                        SendInternal(peer.second, out_msg);
                    }
                    else {
                        size_t unconfirmed_in_count = 0;
                        p2p::frost_message_ptr in_msg = peer_incoming_pipeline(peer.second).PeekUnconfirmedMessage(std::chrono::seconds(7), unconfirmed_in_count);
                        confirmation_wait_count += unconfirmed_in_count;

                        //std::clog << "Check peer's incoming pipeline | current phase: " << static_cast<uint16_t>(peer_outgoing_pipeline(peer.second).GetCurPhase()) << ", unconfirmed count: " << unconfirmed_in_count << std::endl;

                        if (in_msg && peer_outgoing_pipeline(peer.second).GetCurPhase() == m_end_phase) {
                            //std::clog << "Schedule confirmation send for peer" << std::endl;
                            SendInternal(peer.second, nullptr);
                        }
                    }
                }
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
        });

        //std::clog << "^^^^ Confirmation wait count: " << confirmation_wait_count << std::endl;


        if (confirmation_wait_count == 0) {
            m_protocol_confirmation_mutex.unlock();
        }
    });
}


void ZmqService::ListenCycle(p2p::frost_link_handler h)
{
    cex::stream<std::deque<uint8_t>> buffer;

    zmq::socket_t server_sock(zmq_ctx.value(), zmq::socket_type::pull);

    server_sock.bind(m_server_addr);

    std::clog << "Listening at: " << m_server_addr << std::endl;

    for(bool next_block = false;;) {
        try {

            if (!next_block && !buffer.empty()) {
                try {
                    p2p::frost_message_ptr msg = nullptr;
                    try {
                        msg = p2p::Unserialize(m_ctx, buffer);
                    }
                    catch(p2p::WrongMessage e) {
                        if (e.protocol_id != static_cast<uint16_t>(p2p::PROTOCOL::FROST) ||
                            e.message_id != static_cast<uint16_t>(p2p::FROST_MESSAGE::MESSAGE_ID_COUNT))
                        {
                            std::rethrow_exception(std::current_exception());
                        }
                        msg = std::make_shared<p2p::FrostMessage>(static_cast<p2p::FROST_MESSAGE>(e.message_id), move(e.pubkey));
                    }

                    p2p::FROST_MESSAGE last_recv_id = p2p::FROST_MESSAGE::MESSAGE_ID_COUNT;
                    if (buffer.remains() >= sizeof(p2p::FROST_MESSAGE)) {
                        buffer >> last_recv_id;
                    }

                    buffer.clear();

                    std::shared_lock lock(m_peers_mutex);
                    peers_map::iterator peer_it = m_peers.find(msg->pubkey);
                    if (peer_it == m_peers.end()) {
                        throw p2p::WrongMessageData(*msg);
                    }
                    peer_state peer = peer_it->second;
                    lock.unlock();

                    if (m_debug_traces)
                        std::clog << (std::ostringstream() << "++++ " << hex(msg->pubkey).substr(0, 8) << "... -> " << static_cast<uint16_t>(last_recv_id)).str() << std::endl;

                    if (last_recv_id != p2p::FROST_MESSAGE::MESSAGE_ID_COUNT) {
                        peer_outgoing_pipeline(peer).ConfirmPhase(last_recv_id);
                    }

                    if (msg->id != p2p::FROST_MESSAGE::MESSAGE_ID_COUNT) {
                        peer_incoming_pipeline(peer).PushMessage(move(msg));
                        mTaskService->Serve([this, peer, h]() { ProcessIncomingPipeline(peer, h); });
                    }
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
                if (elapsed < std::chrono::milliseconds(50)) {
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

void ZmqService::WaitForConfirmations()
{
    std::lock_guard lock(m_protocol_confirmation_mutex);
}


void FrostMessagePipeLine::PushMessage(p2p::frost_message_ptr msg)
{
    std::lock_guard lock(*m_queue_mutex);
    auto ins_it = std::find_if(m_queue.begin(), m_queue.end(), [msg](const p2p::frost_message_ptr& que_msg){ return que_msg->id > msg->id; });
    m_queue.insert(ins_it, move(msg));
}

p2p::frost_message_ptr FrostMessagePipeLine::PeekNextMessage()
{
    std::lock_guard lock(*m_queue_mutex);
    auto it = std::find_if(m_queue.begin(), m_queue.end(), [this](auto& m){ return m->id == m_next_phase; });
    return (it != m_queue.end()) ? *it : l15::p2p::frost_message_ptr();
}

p2p::frost_message_ptr FrostMessagePipeLine::PeekUnconfirmedMessage(std::chrono::milliseconds confirmation_timeout, size_t& unconfirmed_count)
{
    auto time = std::chrono::steady_clock::now();
    std::lock_guard lock(*m_queue_mutex);
    unconfirmed_count = m_queue.size();
    if ((time - m_last_to_confirm_time > confirmation_timeout) && !m_queue.empty() && m_queue.front()->id < m_next_phase) {
        m_last_to_confirm_time = time;
        return m_queue.front();
    } else {
        return l15::p2p::frost_message_ptr();
    }
}

void FrostMessagePipeLine::PopCurrentMessage()
{
    auto time = std::chrono::steady_clock::now();
    std::lock_guard lock(*m_queue_mutex);
    auto it = std::find_if(m_queue.begin(), m_queue.end(), [this](auto& m){ return m->id == m_next_phase; });
    if (it != m_queue.end()) {
        m_next_phase = static_cast<p2p::FROST_MESSAGE>(static_cast<uint16_t>(m_next_phase) + 1);
        m_last_to_confirm_time = time;
    }
}

void FrostMessagePipeLine::ConfirmPhase(p2p::FROST_MESSAGE confirm_phase)
{
    auto time = std::chrono::steady_clock::now();
    std::list<p2p::frost_message_ptr> confirmed;
    {
        std::lock_guard lock(*m_queue_mutex);
        while (!m_queue.empty() && confirm_phase >= m_queue.front()->id) {
            confirmed.push_back(m_queue.front());
            m_queue.pop_front();
            m_last_to_confirm_time = time;
        }
    }

    for (auto& m: confirmed) {
        std::clog << (std::ostringstream() << "@@@@: " << hex(m_pk).substr(0,8) << "... " << m->ToString()).str() << std::endl;
    }
}


}
