#pragma once

#include <memory>

#include "common_error.hpp"

namespace l15::p2p {

struct Message
{
    Message(uint16_t protocol, uint16_t msg) : protocol_id(protocol), id(msg) {}
    uint16_t protocol_id;
    uint16_t id;
};

class WrongProtocol: public Error {
public:
    explicit WrongProtocol(uint16_t protocol) : protocol_id(protocol) {}
    ~WrongProtocol() override = default;

    const char* what() const override
    { return "WrongProtocol"; }

    uint16_t protocol_id;
};

class WrongMessage: public Error {
public:
    explicit WrongMessage(const Message& m) : protocol_id(m.protocol_id), message_id(m.id) {}
    ~WrongMessage() override = default;

    const char* what() const override
    { return "WrongMessage"; }

    uint16_t protocol_id;
    uint16_t message_id;
};

class WrongMessageData: public Error {
public:
    explicit WrongMessageData(const Message& m) : protocol_id(m.protocol_id), message_id(m.id) {}
    ~WrongMessageData() override = default;

    const char* what() const override
    { return "WrongMessageData"; }

    uint16_t protocol_id;
    uint16_t message_id;
};




class Link
{
public:
    virtual ~Link() = default;

    // Assuming reentrant behavior as per now!!!
    virtual void Send(const Message& m) = 0;
};

typedef std::shared_ptr<Link> link_ptr;

}