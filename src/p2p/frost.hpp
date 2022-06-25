#pragma once

#include "protocol.hpp"
#include "link.hpp"
#include "common_frost.hpp"

namespace l15::p2p {



enum class FROST_MESSAGE: uint16_t {
    REMOTE_SIGNER,
    NONCE_COMMITMENTS,
    KEYSHARE_COMMITMENT,
    KEYSHARE,

    MESSAGE_ID_COUNT
};



struct RemoteSigner : public Message
{
    RemoteSigner(uint32_t idx, const xonly_pubkey& pk) : Message((uint16_t)PROTOCOL::FROST, (uint16_t)FROST_MESSAGE::REMOTE_SIGNER), index(idx), pubkey(pk) {}
    uint32_t index;
    xonly_pubkey pubkey;
};

struct NonceCommitments : public Message
{
    NonceCommitments(uint32_t idx) : Message((uint16_t)PROTOCOL::FROST, (uint16_t)FROST_MESSAGE::NONCE_COMMITMENTS), index(idx) {}
    uint32_t index;
    std::vector<frost_pubnonce> nonce_commitments;
};

struct KeyShareCommitment : public Message
{
    KeyShareCommitment(uint32_t idx) : Message((uint16_t)PROTOCOL::FROST, (uint16_t)FROST_MESSAGE::KEYSHARE_COMMITMENT), index(idx) {}
    uint32_t index;
    std::vector<compressed_pubkey> share_commitment;
};

struct KeyShare : public Message
{
    KeyShare(uint32_t idx) : Message((uint16_t)PROTOCOL::FROST, (uint16_t)FROST_MESSAGE::KEYSHARE), index(idx) {}
    uint32_t index;
    seckey share;
};

}