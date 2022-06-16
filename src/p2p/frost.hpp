#pragma once

#include "protocol.hpp"
#include "link.hpp"
#include "common_frost.hpp"

namespace l15::p2p {



enum class FROST_MESSAGE: uint16_t {
    REMOTE_SIGNER,
    NONCE_COMMITMENTS,

    MESSAGE_ID_COUNT
};



struct RemoteSigner : public Message
{
    uint32_t index;
    xonly_pubkey pubkey;
};

struct NonceCommitments : public Message
{
    uint32_t index;
    std::vector<frost_pubnonce> nonce_commitments;
};

}