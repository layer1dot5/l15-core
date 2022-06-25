#pragma once

#include <memory>

namespace l15::p2p {

struct WrongProtocol
{
    uint16_t protocol_id;
};

struct WrongMessage
{
    uint16_t protocol_id;
    uint16_t message_id;
};

struct WrongMessageData
{
    uint16_t protocol_id;
    uint16_t message_id;
};

struct Message
{
    Message(uint16_t protocol, uint16_t msg) : protocol_id(protocol), id(msg) {}
    uint16_t protocol_id;
    uint16_t id;
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