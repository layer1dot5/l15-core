#pragma once

#include "common.hpp"
#include "common_error.hpp"
#include "channel_keys.hpp"
#include "signer_api.hpp"
#include "signer_service.hpp"


namespace l15::frost {

enum FrostStatus: uint16_t
{
    Ready = 0,
    InProgress = 1,
    Completed = 2,
    Confirmed = 4,
    Error = 8
};

class FrostSigner;


class WrongFrostState: public Error
{
public:
    explicit WrongFrostState(std::string&& details) noexcept : Error(move(details)) {}
    const char* what() const noexcept override { return "WrongFrostState"; }
};

inline uint16_t get_send_status(uint16_t full_status)
{ return full_status >> 8; }

inline uint16_t set_send_status(uint16_t status)
{ return status << 8; }

inline uint16_t get_recv_status(uint16_t full_status)
{ return full_status & 0x0ff; }

inline uint16_t set_recv_status(uint16_t status)
{ return status & 0x0ff; }

inline std::string translate(FrostStatus s)
{
    switch (s) {
    case FrostStatus::Ready:
        return "Ready";
    case FrostStatus::InProgress:
        return "InProgress";
    case FrostStatus::Completed:
        return "Completed";
    case FrostStatus::Confirmed:
        return "Confirmed";
    case FrostStatus::Error:
        return "Error";
    }
}


namespace details {

struct message_status
{
    p2p::frost_message_ptr message;
    FrostStatus status;

    bool operator<(const message_status &other) const
    { return message->id < other.message->id; }
};


enum class OperationType : uint16_t
{
    nonce, key, sign
};

struct OperationMapId
{
    core::operation_id opid;
    OperationType optype;

    std::string describe() const;
};

bool operator<(const OperationMapId &op1, const OperationMapId &op2);

}

}
