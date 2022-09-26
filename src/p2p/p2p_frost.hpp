#pragma once

#include "p2p_protocol.hpp"
#include "p2p_link.hpp"
#include "common_frost.hpp"

namespace l15::p2p {


enum class FROST_MESSAGE: uint16_t {
    NONCE_COMMITMENTS,
    KEY_COMMITMENT,
    KEY_SHARE,
    SIGNATURE_COMMITMENT,
    SIGNATURE_SHARE,

    MESSAGE_ID_COUNT
};


struct NonceCommitments : public Message
{
    NonceCommitments(xonly_pubkey&& pk) : Message((uint16_t)PROTOCOL::FROST, (uint16_t)FROST_MESSAGE::NONCE_COMMITMENTS), pubkey(move(pk)) {}
    xonly_pubkey pubkey;
    std::vector<secp256k1_frost_pubnonce> nonce_commitments;
};

struct KeyShareCommitment : public Message
{
    KeyShareCommitment(xonly_pubkey&& pk) : Message((uint16_t)PROTOCOL::FROST, (uint16_t)FROST_MESSAGE::KEY_COMMITMENT), pubkey(move(pk)) {}
    xonly_pubkey pubkey;
    std::vector<secp256k1_pubkey> share_commitment;
};

struct KeyShare : public Message
{
    KeyShare(xonly_pubkey&& pk) : Message((uint16_t)PROTOCOL::FROST, (uint16_t)FROST_MESSAGE::KEY_SHARE), pubkey(move(pk)) {}
    xonly_pubkey pubkey;
    secp256k1_frost_share share;
};

struct SignatureCommitment : public Message
{
    SignatureCommitment(xonly_pubkey&& pk, uint32_t opid) : Message((uint16_t)PROTOCOL::FROST, (uint16_t)FROST_MESSAGE::SIGNATURE_COMMITMENT), pubkey(move(pk)), operation_id(opid) {}
    xonly_pubkey pubkey;
    uint32_t operation_id;
    // TODO: Looks commitments itself is forgotten!!!
};

struct SignatureShare : public Message
{
    SignatureShare(xonly_pubkey&& pk, uint32_t opid) : Message((uint16_t)PROTOCOL::FROST, (uint16_t)FROST_MESSAGE::SIGNATURE_SHARE), pubkey(move(pk)), operation_id(opid) {}
    xonly_pubkey pubkey;
    uint32_t operation_id;
    frost_sigshare share;
};

}