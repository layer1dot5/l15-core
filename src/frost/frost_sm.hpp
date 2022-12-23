#pragma once

#include <cstdint>
#include <memory>
#include <list>
#include <functional>

#include "common.hpp"
#include "p2p_frost.hpp"


namespace l15::core {
    class SignerApi;
}

namespace l15::frost {

template <typename ST, typename EV>
class State {
public:
    void AddTransition(EV event, std::function<void(EV)> fn);
};


class Peer2PeerSM {

    xonly_pubkey m_peer_pk;
    struct {
        uint16_t sent:1;
        uint16_t sent_confirmed:1;
        uint16_t received:1;
        uint16_t receive_confirmed:1;
    } m_state;

public:
    Peer2PeerSM(xonly_pubkey peer_pk) : m_peer_pk(move(peer_pk)) {}
};

class FrostOperation {
public:
    virtual void ProcessMessage(p2p::frost_message_ptr msg) = 0;
    virtual ~FrostOperation() = default;
};

typedef std::unique_ptr<FrostOperation> operation_ptr;

class KeyAggregationSM : public FrostOperation {
    enum {INIT, KEY_COMMIT, KEY_SHARE, KEY_READY};

public:
    ~KeyAggregationSM() override = default;
    void ProcessMessage(p2p::frost_message_ptr msg);
};

class SignatureAggregationSM : public FrostOperation {
    enum {INIT, SIG_COMMIT, SIG_SHARE, SIG_READY};
public:
    void ProcessMessage(p2p::frost_message_ptr msg);
    ~SignatureAggregationSM() override = default;
};

class FrostSM {
    enum {INIT, KEY_AGG, SIG};

    std::shared_ptr<core::SignerApi> mSigner;

    std::list<std::unique_ptr<FrostOperation>> m_operations;


public:
    explicit FrostSM(std::shared_ptr<core::SignerApi> signer) : mSigner(move(signer)) {}

    void StartOperation(operation_ptr&& op);

    void ProcessMessage(p2p::frost_message_ptr msg);

};


}