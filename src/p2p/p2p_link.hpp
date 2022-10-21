#pragma once

#include <memory>

#include "common_error.hpp"
#include "p2p_protocol.hpp"

namespace l15::p2p {

struct Message
{
    PROTOCOL protocol_id;

    Message() noexcept : protocol_id(PROTOCOL::WRONG_PROTOCOL) {}
    Message(PROTOCOL protocol) noexcept : protocol_id(protocol) {}

    virtual ~Message() = default;

};


class WrongProtocol: public Error {
public:
    explicit WrongProtocol(uint16_t protocol) : protocol_id(protocol) {}
    ~WrongProtocol() override = default;

    const char* what() const override
    { return "WrongProtocol"; }

    uint16_t protocol_id;
};



}