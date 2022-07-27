#pragma once

#include "protocol.hpp"
#include "link.hpp"
#include "common_frost.hpp"

namespace l15::p2p {



enum class FROST_MESSAGE: uint16_t {
    REMOTE_SIGNER,
    NONCE_COMMITMENTS,
    KEY_COMMITMENT,
    KEY_SHARE,
    SIGNATURE_COMMITMENT,
    SIGNATURE_SHARE,

    MESSAGE_ID_COUNT
};



struct RemoteSigner : public Message
{
    RemoteSigner(uint32_t idx, const xonly_pubkey& pk) : Message((uint16_t)PROTOCOL::FROST, (uint16_t)FROST_MESSAGE::REMOTE_SIGNER), peer_index(idx), pubkey(pk) {}
    uint32_t peer_index;
    xonly_pubkey pubkey;
};

struct NonceCommitments : public Message
{
    NonceCommitments(uint32_t idx) : Message((uint16_t)PROTOCOL::FROST, (uint16_t)FROST_MESSAGE::NONCE_COMMITMENTS), peer_index(idx) {}
    uint32_t peer_index;
    std::vector<frost_pubnonce> nonce_commitments;
};

struct KeyShareCommitment : public Message
{
    KeyShareCommitment(uint32_t idx) : Message((uint16_t)PROTOCOL::FROST, (uint16_t)FROST_MESSAGE::KEY_COMMITMENT), peer_index(idx) {}
    uint32_t peer_index;
    std::vector<compressed_pubkey> share_commitment;
};

struct KeyShare : public Message
{
    KeyShare(uint32_t idx) : Message((uint16_t)PROTOCOL::FROST, (uint16_t)FROST_MESSAGE::KEY_SHARE), peer_index(idx) {}
    uint32_t peer_index;
    seckey share;
};

struct SignatureCommitment : public Message
{
    SignatureCommitment(uint32_t idx, uint32_t opid) : Message((uint16_t)PROTOCOL::FROST, (uint16_t)FROST_MESSAGE::SIGNATURE_COMMITMENT), peer_index(idx), operation_id(opid) {}
    uint32_t peer_index;
    uint32_t operation_id;
};

struct SignatureShare : public Message
{
    SignatureShare(uint32_t idx, uint32_t opid) : Message((uint16_t)PROTOCOL::FROST, (uint16_t)FROST_MESSAGE::SIGNATURE_SHARE), peer_index(idx), operation_id(opid) {}
    uint32_t peer_index;
    uint32_t operation_id;
    frost_sigshare share;
};

}