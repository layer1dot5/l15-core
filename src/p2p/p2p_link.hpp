#pragma once

#include <memory>
#include <functional>
#include <sstream>

#include "common_error.hpp"
#include "p2p_protocol.hpp"

namespace l15::p2p {

struct Message
{
    PROTOCOL protocol_id; //uint16_t
    uint16_t sequence;

    Message() noexcept : protocol_id(PROTOCOL::WRONG_PROTOCOL), sequence(1) {}
    explicit Message(PROTOCOL protocol, uint16_t seq) noexcept : protocol_id(protocol), sequence(seq) {}

    virtual ~Message() = default;
};


class WrongProtocol: public Error {
public:
    explicit WrongProtocol(uint16_t protocol) : Error((std::ostringstream() << protocol).str()) {}
    ~WrongProtocol() override = default;

    const char* what() const noexcept override
    { return "WrongProtocol"; }
};


template <class ADDR, class MESSAGE>
class P2PInterface {
public:
    virtual void Publish(std::shared_ptr<MESSAGE>,
                         std::function<void(const ADDR&, std::shared_ptr<MESSAGE>)> on_send,
                         std::function<void(const ADDR&, std::shared_ptr<MESSAGE>)> on_error) = 0;

    virtual void Send(const ADDR&, std::shared_ptr<MESSAGE>,
                      std::function<void()> on_error) = 0;

    virtual void Connect(const ADDR&, std::function<void(std::shared_ptr<MESSAGE>)>) = 0;

    virtual ~P2PInterface() = default;
};


}