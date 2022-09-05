#pragma once

#include <optional>
#include <memory>

#include "common.hpp"
#include "common_error.hpp"

#include "script/script.h"

namespace l15::onchain {

enum class ProtocolMagic {
    MEMBER_COMMITMENT_V0 = 0x3745
};


class OnChainFormatError : public Error {
    const char* m_details;
public:
    OnChainFormatError() : m_details("") {}
    OnChainFormatError(const OnChainFormatError&) = default;
    explicit OnChainFormatError(const char* details) : m_details(details) {}
    ~OnChainFormatError() override = default;
    OnChainFormatError& operator=(const OnChainFormatError&) = default;

    const char* what() const override
    { return "OnChainFormatError"; }

    const char* details() const override
    { return m_details; }

};


#pragma pack(push, 1)

//template <class T>
//union OnChainData {
//    uint8_t script[];
//    T data;
//};

struct NonceCommitment {
    uint8_t p1[33];
    uint8_t p2[33];
};

struct NonceCommitments {
    uint8_t magic[2];
    uint8_t count;
    NonceCommitment commitments[];
};

#pragma pack(pop)




}