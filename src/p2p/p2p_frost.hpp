#pragma once

#include <algorithm>
#include <type_traits>

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

//TODO: below stream operators work for byte based streams only

template <typename STREAM>
STREAM& operator << (STREAM& s, const FROST_MESSAGE& p)
{ return s << static_cast<std::underlying_type<FROST_MESSAGE>::type>(p); }

template <typename STREAM>
STREAM& operator >> (STREAM& s, FROST_MESSAGE& p)
{ return s >> reinterpret_cast<std::underlying_type<FROST_MESSAGE>::type&>(p); }


class FrostMessage : public Message
{
public:
    FROST_MESSAGE id;
    xonly_pubkey pubkey;

    FrostMessage(FROST_MESSAGE msg_id, xonly_pubkey&& pk): Message(PROTOCOL::FROST), id(msg_id), pubkey(move(pk)) {}
    FrostMessage(FrostMessage&& r) noexcept : Message(PROTOCOL::FROST), id(r.id), pubkey(move(r.pubkey)) {}

    template <typename STREAM>
    void Serialize(STREAM& stream)
    { stream << protocol_id << id << pubkey; }

    template <typename STREAM>
    void Unserialize(STREAM& stream)
    { stream >> protocol_id >> id >> pubkey; }

    ~FrostMessage() = default;

protected:
    FrostMessage() : Message(PROTOCOL::WRONG_PROTOCOL), id(FROST_MESSAGE::MESSAGE_ID_COUNT), pubkey() {}

    template<typename STREAM>
    friend std::unique_ptr<Message> Unserialize(const secp256k1_context* ctx, STREAM& stream);
};


class WrongMessage: public Error {
public:
    explicit WrongMessage(const FrostMessage& m) : protocol_id(static_cast<uint16_t>(m.protocol_id)), message_id(static_cast<uint16_t>(m.id)) {}
    ~WrongMessage() override = default;

    const char* what() const override
    { return "WrongMessage"; }

    uint16_t protocol_id;
    uint16_t message_id;
};

class WrongMessageData: public Error {
public:
    explicit WrongMessageData(const FrostMessage& m) : protocol_id(static_cast<uint16_t>(m.protocol_id)), message_id(static_cast<uint16_t>(m.id)) {}
    ~WrongMessageData() override = default;

    const char* what() const override
    { return "WrongMessageData"; }

    uint16_t protocol_id;
    uint16_t message_id;
};


class NonceCommitments : public FrostMessage
{
public:
    std::vector<secp256k1_frost_pubnonce> nonce_commitments;

    NonceCommitments(xonly_pubkey&& pk) : FrostMessage(FROST_MESSAGE::NONCE_COMMITMENTS, move(pk)) {}
    NonceCommitments(NonceCommitments&& r) : FrostMessage(move(r)), nonce_commitments(move(r.nonce_commitments)) {}

    template <typename STREAM>
    void Serialize(const secp256k1_context* ctx, STREAM& stream)
    {
        uint8_t buf[66];
        FrostMessage::Serialize(stream);

        std::for_each(nonce_commitments.begin(), nonce_commitments.end(), [&](const auto& nonce) {
            if (!secp256k1_frost_pubnonce_serialize(ctx, buf, &nonce)) {
                throw std::runtime_error("FROST pubnonce serialize error");
            }
            stream.write(buf, 66);
        });
    }

    template <typename STREAM>
    void Unerialize(const secp256k1_context* ctx, STREAM& stream)
    {
        FrostMessage::Unserialize(stream);

        size_t pubnonce_count = stream.remains() / 66;
        if ((pubnonce_count * 66) !=  stream.remains()) {
            throw std::runtime_error("NonceCommitments message size is wrong");
        }
        nonce_commitments.resize(pubnonce_count);

        auto nonce_it = nonce_commitments.begin();

        while (stream.remains()) {
            const uint8_t* data = stream.read_pointer();
            stream.expand(66);
            if (!secp256k1_frost_pubnonce_parse(ctx, &(*nonce_it++), data)) {
                nonce_commitments.clear();
                throw std::runtime_error("FROST pubnonce unserialize error");
            }
        }
    }
private:
    NonceCommitments() : FrostMessage(), nonce_commitments() {}

    template<typename STREAM>
    friend std::unique_ptr<Message> Unserialize(const secp256k1_context* ctx, STREAM& stream);
};

class KeyShareCommitment : public FrostMessage
{
public:
    std::vector<secp256k1_pubkey> share_commitment;

    KeyShareCommitment(xonly_pubkey&& pk) : FrostMessage(FROST_MESSAGE::KEY_COMMITMENT, move(pk)) {}
    KeyShareCommitment(KeyShareCommitment&& r) : FrostMessage(move(r)), share_commitment(move(r.share_commitment)) {}

    template <typename STREAM>
    void Serialize(const secp256k1_context* ctx, STREAM& stream)
    {
        uint8_t buf[33];
        size_t buflen = 33;
        FrostMessage::Serialize(stream);

        std::for_each(share_commitment.begin(), share_commitment.end(), [&](const auto& comm) {
            if (!secp256k1_ec_pubkey_serialize(ctx, buf, &buflen, &comm, SECP256K1_EC_COMPRESSED)) {
                throw std::runtime_error("FROST key share commitment serialize error");
            }
            stream.write(buf, 33);

        });
    }

    template <typename STREAM>
    void Unerialize(const secp256k1_context* ctx, STREAM& stream)
    {
        FrostMessage::Unserialize(stream);

        size_t count = stream.remains() / 33;
        if ((count * 33) !=  stream.remains()) {
            throw std::runtime_error("KeyShareCommitment message size is wrong");
        }
        share_commitment.resize(count);

        auto comm_it = share_commitment.begin();

        while (stream.remains()) {
            const uint8_t* data = stream.read_pointer();
            stream.expand(33);
            if (!secp256k1_ec_pubkey_parse(ctx, &(*comm_it++), data, 33)) {
                share_commitment.clear();
                throw std::runtime_error("FROST key share commitment unserialize error");
            }
        }
    }
private:
    KeyShareCommitment() : FrostMessage(), share_commitment() {}

    template<typename STREAM>
    friend std::unique_ptr<Message> Unserialize(const secp256k1_context* ctx, STREAM& stream);
};

class KeyShare : public FrostMessage
{
public:
    secp256k1_frost_share share;

    KeyShare(xonly_pubkey&& pk) : FrostMessage(FROST_MESSAGE::KEY_SHARE, move(pk)) {}
    KeyShare(KeyShare&& r): FrostMessage(move(r)), share(r.share) {}

    template <typename STREAM>
    void Serialize(const secp256k1_context* ctx, STREAM& stream)
    {
        FrostMessage::Serialize(stream);
        stream.write(share.data, sizeof(share.data));
    }

    template <typename STREAM>
    void Unerialize(const secp256k1_context* ctx, STREAM& stream)
    {
        FrostMessage::Unserialize(stream);

        if (sizeof(share.data) !=  stream.remains()) {
            throw std::runtime_error("KeyShare message size is wrong");
        }

        stream.read(share.data, sizeof(share.data));
    }

private:
    KeyShare() : FrostMessage(), share{} {}

    template<typename STREAM>
    friend std::unique_ptr<Message> Unserialize(const secp256k1_context* ctx, STREAM& stream);
};

class SignatureCommitment : public FrostMessage
{
public:
    uint32_t operation_id;
    SignatureCommitment(xonly_pubkey&& pk, uint32_t opid) : FrostMessage(FROST_MESSAGE::SIGNATURE_COMMITMENT, move(pk)), operation_id(opid) {}
    SignatureCommitment(SignatureCommitment&& r) : FrostMessage(move(r)), operation_id(r.operation_id) {}

    template <typename STREAM>
    void Serialize(const secp256k1_context* ctx, STREAM& stream)
    {
        FrostMessage::Serialize(stream);
        stream << operation_id;
    }

    template <typename STREAM>
    void Unerialize(const secp256k1_context* ctx, STREAM& stream)
    {
        FrostMessage::Unserialize(stream);
        stream >> operation_id;
    }

private:
    SignatureCommitment() : FrostMessage(), operation_id(0) {}

    template<typename STREAM>
    friend std::unique_ptr<Message> Unserialize(const secp256k1_context* ctx, STREAM& stream);
};

class SignatureShare : public FrostMessage
{
public:
    uint32_t operation_id;
    frost_sigshare share;

    SignatureShare(xonly_pubkey&& pk, uint32_t opid) : FrostMessage(FROST_MESSAGE::SIGNATURE_SHARE, move(pk)), operation_id(opid), share{} {}
    SignatureShare(SignatureShare&& r) : FrostMessage(move(r)), operation_id(r.operation_id), share(move(r.share)) {}

    template <typename STREAM>
    void Serialize(const secp256k1_context* ctx, STREAM& stream)
    {
        FrostMessage::Serialize(stream);
        stream << operation_id << share;
    }

    template <typename STREAM>
    void Unerialize(const secp256k1_context* ctx, STREAM& stream)
    {
        FrostMessage::Unserialize(stream);
        stream >> operation_id >> share;
    }

private:
    SignatureShare() : FrostMessage(), operation_id(0), share() {}

    template<typename STREAM>
    friend std::unique_ptr<Message> Unserialize(const secp256k1_context* ctx, STREAM& stream);
};

template<typename STREAM>
std::unique_ptr<Message> Unserialize(const secp256k1_context* ctx, STREAM& stream)
{
    FrostMessage header;
    auto pos = stream.position();
    header.Unserialize(stream);
    stream.rewind(stream.position() - pos);

    switch (header.id) {
    case FROST_MESSAGE::NONCE_COMMITMENTS:
        {
            NonceCommitments msg;
            msg.Unerialize(ctx, stream);
            return std::make_unique<NonceCommitments>(move(msg));
        }
    case FROST_MESSAGE::KEY_COMMITMENT:
        {
            KeyShareCommitment msg;
            msg.Unerialize(ctx, stream);
            return std::make_unique<KeyShareCommitment>(move(msg));
        }
    case FROST_MESSAGE::KEY_SHARE:
        {
            KeyShare msg;
            msg.Unerialize(ctx, stream);
            return std::make_unique<KeyShare>(move(msg));
        }
    case FROST_MESSAGE::SIGNATURE_COMMITMENT:
        {
            SignatureCommitment msg;
            msg.Unerialize(ctx, stream);
            return std::make_unique<SignatureCommitment>(move(msg));
        }
    case FROST_MESSAGE::SIGNATURE_SHARE:
        {
            SignatureShare msg;
            msg.Unerialize(ctx, stream);
            return std::make_unique<SignatureShare>(move(msg));
        }
    default:
        throw WrongMessage(header);
    }
}


}
