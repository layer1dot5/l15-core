
#include <algorithm>
#include <ranges>
#include <deque>
#include <memory>

#include "frost_steps.hpp"
#include "frost_signer.hpp"

namespace l15::frost {

namespace rgs = std::ranges;
namespace vs = std::views;


namespace {

details::message_queue& send_queue(details::peer_messages& cache)
{ return std::get<0>(cache); }

std::shared_mutex& send_mutex(details::peer_messages& cache)
{ return *std::get<1>(cache); }

details::message_queue& recv_queue(details::peer_messages& cache)
{ return std::get<2>(cache); }

std::shared_mutex& recv_mutex(details::peer_messages& cache)
{ return *std::get<3>(cache); }

void push_with_priority(details::message_queue& queue, p2p::frost_message_ptr m)
{
    auto it = std::find_if(queue.rbegin(), queue.rend(), [&](const auto &s) {
        return s.message->id <= m->id;
    });
    if (it == queue.rend() || it->message->id != m->id) {
        details::message_status s = {m, FrostStatus::Ready};
        queue.emplace(it.base(), move(s));
    }
    else {
        it->message = move(m);
    }

    queue.emplace_back(details::message_status{m, FrostStatus::Ready});
    std::sort(queue.begin(), queue.end());
}

}


bool FrostStep::CheckAndQueueSendImpl(FrostSignerBase& signer, const std::optional<const xonly_pubkey> &peer_pk, p2p::frost_message_ptr m,
                                      p2p::FROST_MESSAGE frost_step)
{
    bool res;
    bool is_completed = (get_send_status(m_status) & (uint16_t)FrostStatus::Completed);
    if ((res = m->id == frost_step && !is_completed )) {
        if (peer_pk) {
            auto peer_it = signer.PeersCache().find(*peer_pk);
            if ((res = peer_it != signer.PeersCache().end())) {
                std::unique_lock lock(send_mutex(peer_it->second));
                push_with_priority(send_queue(peer_it->second), m);
            }
            else {
                throw p2p::WrongAddress(hex(*peer_pk));
            }
        }
        else {
            std::for_each(std::execution::par, signer.PeersCache().begin(), signer.PeersCache().end(), [m](auto& peer){
                std::unique_lock lock(send_mutex(peer.second));
                push_with_priority(send_queue(peer.second), m);
            });
        }
    }
    return res;
}

bool FrostStep::CheckAndQueueReceiveImpl(FrostSignerBase& signer, p2p::frost_message_ptr m, p2p::FROST_MESSAGE frost_step)
{
    bool res = false;
    if ((m->id == frost_step && !(get_recv_status(m_status) & (uint16_t) FrostStatus::Completed) )) {
        auto peer_it = signer.PeersCache().find(m->pubkey);
        if ((res = peer_it != signer.PeersCache().end())) {
            std::unique_lock lock(recv_mutex(peer_it->second));
            push_with_priority(recv_queue(peer_it->second), m);
        }
        else {
            throw p2p::WrongAddress(hex(m->pubkey));
        }

        // Check the step is already started (means start to send its messages)
        res = (get_send_status(m_status) & (uint16_t)FrostStatus::InProgress);
    }
    return res;
}

void FrostStep::DefaultSend(FrostSignerBase& signer, const xonly_pubkey& peer_pk, details::message_status& send_status, uint16_t confirm_seq) const
{
    if (send_status.status != FrostStatus::Confirmed) { //Check the message status

        p2p::frost_message_ptr send_msg = send_status.message->Copy();

        send_msg->confirmed_sequence = confirm_seq;

        signer.PeerService().Send(peer_pk, send_msg, [s = mSigner](){
            //TODO: send_status.status = FrostStatus::Error
            if (auto signer = s.lock()) signer->HandleError();
        });

        send_status.status = FrostStatus::Completed;
    }
}

bool FrostStep::DefaultReceive(FrostSignerBase& signer, details::message_status &recv_status) const
{
    if (recv_status.status == FrostStatus::Ready) {
        recv_status.status = FrostStatus::InProgress; //Really, excessive since the message processing happens under mutex lock
        signer.SignerService().Accept(signer.SignerApi(), recv_status.message);
        recv_status.status = FrostStatus::Completed;
        return true;
    }
    // else it's a duplicate of some already accepted message
    return false;
}


bool NonceCommit::MessageSend(FrostSignerBase& signer, const std::optional<const xonly_pubkey> &peer_pk)
{
    if (peer_pk) throw std::runtime_error("NonceCommit: send with peer pubkey");

    for (auto &peer: signer.PeersCache()) {
        uint16_t confirm_seq = 0;
        {   std::shared_lock recv_lock(recv_mutex(peer.second));
            if (!recv_queue(peer.second).empty())
                confirm_seq = rgs::max(recv_queue(peer.second) | vs::transform([](auto &s) { return s.message->confirmed_sequence; }));
        }

        std::unique_lock send_lock(send_mutex(peer.second));

        auto send_it = rgs::find_if(send_queue(peer.second), [](const auto& s){
            return s.message->id == p2p::FROST_MESSAGE::NONCE_COMMITMENTS && s.status == FrostStatus::Ready;
        });
        if (send_it != send_queue(peer.second).end()) {
            DefaultSend(signer, peer.first, *send_it, confirm_seq);
        }
    }

    return false;
}

bool NonceCommit::MessageReceive(FrostSignerBase& signer, details::peer_messages &peer_cache)
{
    std::unique_lock recv_lock(recv_mutex(peer_cache));

    auto recv_it = rgs::find_if(recv_queue(peer_cache), [](const auto& s){
        return s.message->id == p2p::FROST_MESSAGE::NONCE_COMMITMENTS && s.status == FrostStatus::Ready;
    });
    if (recv_it != recv_queue(peer_cache).end()) {
        DefaultReceive(signer, *recv_it);
    }
    return false;
}


bool KeyShare::MessageSend(FrostSignerBase& signer, const std::optional<const xonly_pubkey> &peer_pk)
{
    uint16_t status = SendStatus();
    if ((!(status & FrostStatus::InProgress)) || (status & FrostStatus::Completed))
        return false;

    if (!peer_pk) throw std::runtime_error("KeyShare: send without peer pubkey");

    auto &peer = signer.PeersCache().at(*peer_pk);

    uint16_t confirm_seq = 0;
    {   std::shared_lock recv_lock(recv_mutex(peer));
        if (!recv_queue(peer).empty())
            confirm_seq = rgs::max(recv_queue(peer) | vs::transform([](auto &s) { return s.message->confirmed_sequence; }));
    }

    std::unique_lock send_lock(send_mutex(peer));

    auto send_it = rgs::find_if(send_queue(peer), [](const auto &s) {
        return s.message->id == p2p::FROST_MESSAGE::KEY_SHARE && s.status == FrostStatus::Ready;
    });
    if (send_it != send_queue(peer).end()) {
        DefaultSend(signer, *peer_pk, *send_it, confirm_seq);

        if (++keyshares_sent >= (signer.N - 1)) {
            SendStatus(FrostStatus::Completed);

            if (IsCompleted()) {
                std::clog << (std::ostringstream() << "KeyShare p2p completed: " << hex(signer.SignerApi()->GetLocalPubKey()).substr(0, 8)).str() << std::endl;
            }

            return true;
        }
    }
    return false;
}

bool KeyShare::MessageReceive(FrostSignerBase& signer, details::peer_messages &peer_cache)
{
    std::unique_lock recv_lock(recv_mutex(peer_cache));

    auto recv_it = rgs::find_if(recv_queue(peer_cache), [](const auto& s){
        return s.message->id == p2p::FROST_MESSAGE::KEY_SHARE && s.status == FrostStatus::Ready;
    });
    if (recv_it != recv_queue(peer_cache).end() && DefaultReceive(signer, *recv_it) && ++keyshares_received >= (signer.N - 1)) {
        RecvStatus(FrostStatus::Completed);

        if (IsCompleted()) {
            std::clog << (std::ostringstream() << "KeyShare p2p completed: " << hex(signer.SignerApi()->GetLocalPubKey()).substr(0, 8)).str() << std::endl;
        }

        return true;
    }
    return false;
}

bool KeyCommit::MessageSend(FrostSignerBase& signer, const std::optional<const xonly_pubkey> &peer_pk)
{
    uint16_t status = SendStatus();
    if ((!(status & FrostStatus::InProgress)) || (status & FrostStatus::Completed))
        return false;

    if (peer_pk) throw std::runtime_error("KeyCommit send with peer pubkey");

    for (auto &peer: signer.PeersCache()) {
        uint16_t confirm_seq = 0;
        {   std::shared_lock recv_lock(recv_mutex(peer.second));
            if (!recv_queue(peer.second).empty())
                confirm_seq = rgs::max(recv_queue(peer.second)|vs::transform([](auto& s){ return s.message->confirmed_sequence; }));
        }

        std::unique_lock send_lock(send_mutex(peer.second));

        auto send_it = rgs::find_if(send_queue(peer.second), [](const auto& s){
            return s.message->id == p2p::FROST_MESSAGE::KEY_COMMITMENT && s.status == FrostStatus::Ready;
        });
        if (send_it != send_queue(peer.second).end()) {
            DefaultSend(signer, peer.first, *send_it, confirm_seq);
        }
    }
    SendStatus(FrostStatus::Completed);
    return true;
}

bool KeyCommit::MessageReceive(FrostSignerBase& signer, details::peer_messages &peer_cache)
{
    std::unique_lock recv_lock(recv_mutex(peer_cache));
    auto recv_it = rgs::find_if(recv_queue(peer_cache), [](const auto& s){
        return s.message->id == p2p::FROST_MESSAGE::KEY_COMMITMENT && s.status == FrostStatus::Ready;
    });
    if (recv_it != recv_queue(peer_cache).end() && DefaultReceive(signer, *recv_it) && ++commitments_received >= (signer.N - 1)) {
        RecvStatus(FrostStatus::Completed);
        return true;
    }
    return false;
}

bool SigAgg::MessageSend(FrostSignerBase& signer, const std::optional<const xonly_pubkey> &peer_pk)
{
    uint16_t status = SendStatus();
    if ((!(status & FrostStatus::InProgress)) || (status & FrostStatus::Completed))
        return false;

    if (peer_pk) throw std::runtime_error("SigAgg: send with peer pubkey");

    //auto &peer = signer.PeersCache().at(*peer_pk);
    for (auto &peer: signer.PeersCache()) {

        uint16_t confirm_seq = 0;
        {   std::shared_lock recv_lock(recv_mutex(peer.second));
            if (!recv_queue(peer.second).empty())
                confirm_seq = rgs::max(recv_queue(peer.second)|vs::transform([](auto& s){ return s.message->confirmed_sequence; }));
        }

        std::unique_lock send_lock(send_mutex(peer.second));

        auto send_it = rgs::find_if(send_queue(peer.second), [](const auto &s) {
            return s.message->id == p2p::FROST_MESSAGE::SIGNATURE_SHARE && s.status == FrostStatus::Ready;
        });
        if (send_it != send_queue(peer.second).end()) {
            DefaultSend(signer, peer.first, *send_it, confirm_seq);
        }
    }

    SendStatus(FrostStatus::Completed);
    return true;
}

bool SigAgg::MessageReceive(FrostSignerBase& signer, details::peer_messages &peer_cache)
{
    std::unique_lock recv_lock(recv_mutex(peer_cache));

    auto recv_it = rgs::find_if(recv_queue(peer_cache), [](const auto& s){
        return s.message->id == p2p::FROST_MESSAGE::SIGNATURE_SHARE && s.status == FrostStatus::Ready;
    });
    if (recv_it != recv_queue(peer_cache).end() && DefaultReceive(signer, *recv_it) && ++sigshares_received >= (signer.K - 1)) {
        RecvStatus(FrostStatus::Completed);
        return true;
    }
    return false;
}

bool SigCommit::MessageSend(FrostSignerBase& signer, const std::optional<const xonly_pubkey> &peer_pk)
{
    uint16_t status = SendStatus();
    if ((!(status & FrostStatus::InProgress)) || (status & FrostStatus::Completed))
        return false;

    if (peer_pk) throw std::runtime_error("SigCommit: send with peer pubkey");

    for (auto &peer: signer.PeersCache()) {
        uint16_t confirm_seq = 0;
        {   std::shared_lock recv_lock(recv_mutex(peer.second));
            if (!recv_queue(peer.second).empty())
                confirm_seq = rgs::max(recv_queue(peer.second)|vs::transform([](auto& s){ return s.message->confirmed_sequence; }));
        }

        std::unique_lock send_lock(send_mutex(peer.second));

        auto send_it = rgs::find_if(send_queue(peer.second), [](const auto& s){
            return s.message->id == p2p::FROST_MESSAGE::SIGNATURE_COMMITMENT && s.status == FrostStatus::Ready;
        });
        if (send_it != send_queue(peer.second).end()) {
            DefaultSend(signer, peer.first, *send_it, confirm_seq);
        }
    }
    SendStatus(FrostStatus::Completed);
    return true;
}

bool SigCommit::MessageReceive(FrostSignerBase& signer, details::peer_messages &peer_cache)
{
    std::unique_lock recv_lock(recv_mutex(peer_cache));

    auto recv_it = rgs::find_if(recv_queue(peer_cache), [](const auto& s){
        return s.message->id == p2p::FROST_MESSAGE::SIGNATURE_COMMITMENT && s.status == FrostStatus::Ready;
    });
    if (recv_it != recv_queue(peer_cache).end() && DefaultReceive(signer, *recv_it) && ++commitments_received >= (signer.K - 1)) {
        RecvStatus(FrostStatus::Completed);
        return true;
    }
    return false;
}
}