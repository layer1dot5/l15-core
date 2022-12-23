#pragma once

#include <memory>
#include <functional>
#include <sstream>

#include "common_error.hpp"
#include "p2p_protocol.hpp"

namespace l15::p2p {

struct Message
{
    PROTOCOL protocol_id;

    Message() noexcept : protocol_id(PROTOCOL::WRONG_PROTOCOL) {}
    explicit Message(PROTOCOL protocol) noexcept : protocol_id(protocol) {}

    virtual ~Message() = default;

};


class WrongProtocol: public Error {
public:
    explicit WrongProtocol(uint16_t protocol) : Error((std::ostringstream() << protocol).str()) {}
    ~WrongProtocol() override = default;

    const char* what() const noexcept override
    { return "WrongProtocol"; }
};

class WrongPeer: public Error {
public:
    explicit WrongPeer(std::string&& peer) : Error(move(peer)) {}

    const char* what() const noexcept override
    { return "WrongPeer"; }
};

template <class ADDR, class MESSAGE>
class P2PInterface {
public:
    virtual void Publish(std::shared_ptr<MESSAGE>) = 0;
    virtual void Send(const ADDR&, std::shared_ptr<MESSAGE>) = 0;
    virtual void Subscribe(const ADDR&, std::function<void(std::shared_ptr<MESSAGE>)>) = 0;

    virtual ~P2PInterface() = default;
};


}