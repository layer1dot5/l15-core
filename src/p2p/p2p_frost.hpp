#pragma once

#include <algorithm>
#include <type_traits>

#include "smartinserter.hpp"

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


template <typename STREAM>
STREAM& operator << (STREAM& s, const FROST_MESSAGE& p)
{ return s << static_cast<std::underlying_type<FROST_MESSAGE>::type>(p); }

template <typename STREAM>
STREAM& operator >> (STREAM& s, FROST_MESSAGE& p)
{ return s >> reinterpret_cast<std::underlying_type<FROST_MESSAGE>::type&>(p); }

class FrostMessage;

typedef std::shared_ptr<FrostMessage> frost_message_ptr;
typedef std::function<void(frost_message_ptr)> frost_link_handler;

class FrostMessage : public Message
{
public:
    FROST_MESSAGE id;
    xonly_pubkey pubkey;

    FrostMessage(FROST_MESSAGE msg_id, xonly_pubkey&& pk): Message(PROTOCOL::FROST), id(msg_id), pubkey(move(pk)) {}
    FrostMessage(FrostMessage&& r) noexcept : Message(PROTOCOL::FROST), id(r.id), pubkey(move(r.pubkey)) {}

    template <typename STREAM>
    void Serialize(STREAM& stream) const
    { stream << protocol_id << id << pubkey; }

    template <typename STREAM>
    void Unserialize(STREAM& stream)
    { stream >> protocol_id >> id >> pubkey; }

    ~FrostMessage() override = default;

    virtual std::string ToString() const
    { return ""; };

protected:
    FrostMessage() : Message(PROTOCOL::WRONG_PROTOCOL), id(FROST_MESSAGE::MESSAGE_ID_COUNT), pubkey() {}

    template<typename STREAM>
    friend frost_message_ptr Unserialize(const secp256k1_context* ctx, STREAM& stream);
};



class WrongMessage: public Error {
public:
    explicit WrongMessage(const FrostMessage& m) :
        protocol_id(static_cast<uint16_t>(m.protocol_id)),
        message_id(static_cast<uint16_t>(m.id)),
        pubkey(m.pubkey){}

    ~WrongMessage() override = default;

    const char* what() const noexcept override
    { return "WrongMessage"; }

    uint16_t protocol_id;
    uint16_t message_id;
    xonly_pubkey pubkey;
};

class WrongMessageData: public Error {
public:
    explicit WrongMessageData(const FrostMessage& m) : protocol_id(static_cast<uint16_t>(m.protocol_id)), message_id(static_cast<uint16_t>(m.id)) {}
    ~WrongMessageData() override = default;

    const char* what() const noexcept override
    { return "WrongMessageData"; }

    uint16_t protocol_id;
    uint16_t message_id;
};

class UnserializeError : public Error {
public:
    explicit UnserializeError(std::string&& hexdata) noexcept : Error(move(hexdata)) {}

    const char* what() const noexcept override
    { return "UnserializeError"; }

};


class NonceCommitments : public FrostMessage
{
public:
    std::vector<secp256k1_frost_pubnonce> nonce_commitments;

    explicit NonceCommitments(xonly_pubkey&& pk) noexcept : FrostMessage(FROST_MESSAGE::NONCE_COMMITMENTS, move(pk)) {}
    NonceCommitments(NonceCommitments&& r) noexcept : FrostMessage(move(r)), nonce_commitments(move(r.nonce_commitments)) {}

    template <typename STREAM>
    void Serialize(const secp256k1_context* ctx, STREAM& stream) const
    {
        uint8_t buf[66];
        FrostMessage::Serialize(stream);

        std::for_each(nonce_commitments.begin(), nonce_commitments.end(), [&](const auto& nonce) {
            if (!secp256k1_frost_pubnonce_serialize(ctx, buf, &nonce)) {
                std::stringstream hexstr;
                hexstr << hex(stream);
                throw UnserializeError(hexstr.str());
            }
            stream.write(buf, sizeof(buf));
        });
    }

    template <typename STREAM>
    void Unserialize(const secp256k1_context* ctx, STREAM& stream)
    {
        FrostMessage::Unserialize(stream);

        if (stream.remains() < 66) {
            std::stringstream hexstr;
            hexstr << hex(stream);
            throw UnserializeError(hexstr.str());
        }
        size_t pubnonce_count = stream.remains() / 66;

        nonce_commitments.clear();
        nonce_commitments.reserve(pubnonce_count);

        auto nonce_it = cex::smartinserter(nonce_commitments, nonce_commitments.end());

        uint8_t buf[66];
        const size_t buflen = sizeof(buf);
        secp256k1_frost_pubnonce cur_pubnonce;

        while (stream.remains() >= buflen) {
            stream.read(buf, buflen);
            if (!secp256k1_frost_pubnonce_parse(ctx, &cur_pubnonce, buf)) {
                nonce_commitments.clear();
                std::stringstream hexstr;
                hexstr << hex(stream);
                throw UnserializeError(hexstr.str());
            }
            *nonce_it = cur_pubnonce;
            ++nonce_it;
        }
    }

    std::string ToString() const override
    {
        std::stringstream buf;
        buf << "NonceCommitments {pk: " << hex(pubkey).substr(0, 8) << "...}";
        return move(buf.str());
    }

private:
    NonceCommitments() : FrostMessage(), nonce_commitments() {}

    template<typename STREAM>
    friend frost_message_ptr Unserialize(const secp256k1_context* ctx, STREAM& stream);
};

class KeyShareCommitment : public FrostMessage
{
public:
    std::vector<secp256k1_pubkey> share_commitment;

    explicit KeyShareCommitment(xonly_pubkey&& pk) noexcept : FrostMessage(FROST_MESSAGE::KEY_COMMITMENT, move(pk)) {}
    KeyShareCommitment(KeyShareCommitment&& r) noexcept: FrostMessage(move(r)), share_commitment(move(r.share_commitment)) {}

    template <typename STREAM>
    void Serialize(const secp256k1_context* ctx, STREAM& stream) const
    {
        uint8_t buf[33];
        const size_t buflen = sizeof(buf);
        FrostMessage::Serialize(stream);

        std::for_each(share_commitment.begin(), share_commitment.end(), [&](const auto& comm) {
            size_t outlen = buflen;
            if (!secp256k1_ec_pubkey_serialize(ctx, buf, &outlen, &comm, SECP256K1_EC_COMPRESSED)) {
                throw std::runtime_error("FROST key share commitment serialize error");
            }
            if (outlen != buflen) {
                throw std::runtime_error("FROST key share commitment serialize error: wrong data output length");
            }

            stream.write(buf, buflen);
        });
    }

    template <typename STREAM>
    void Unserialize(const secp256k1_context* ctx, STREAM& stream)
    {
        FrostMessage::Unserialize(stream);

        size_t count = stream.remains() / 33;
        if (count < 3) {
            std::stringstream hexstr;
            hexstr << hex(stream);
            throw UnserializeError(hexstr.str());
        }
        share_commitment.clear();
        share_commitment.reserve(count);

        auto comm_it = cex::smartinserter(share_commitment, share_commitment.end());

        uint8_t buf[33];
        const size_t keysize = sizeof(buf);
        secp256k1_pubkey cur_pk;

        while (stream.remains() >= keysize) {
            stream.read(buf, keysize);
            if (!secp256k1_ec_pubkey_parse(ctx, &cur_pk, buf, keysize)) {
                share_commitment.clear();
                std::stringstream hexstr;
                hexstr << stream.size() << " bytes\n" << hex(stream);
                throw UnserializeError(hexstr.str());
            }
            *comm_it = cur_pk;
            ++comm_it;
        }
    }

    std::string ToString() const override
    {
        std::stringstream buf;
        buf << "KeyShareCommitment {pk: " << hex(pubkey).substr(0, 8) << "...}";
        return move(buf.str());
    }

private:
    KeyShareCommitment() : FrostMessage(), share_commitment() {}

    template<typename STREAM>
    friend frost_message_ptr Unserialize(const secp256k1_context* ctx, STREAM& stream);
};

class KeyShare : public FrostMessage
{
public:
    secp256k1_frost_share share;

    explicit KeyShare(xonly_pubkey&& pk) noexcept : FrostMessage(FROST_MESSAGE::KEY_SHARE, move(pk)) {}
    KeyShare(KeyShare&& r) noexcept: FrostMessage(move(r)), share(r.share) {}

    template <typename STREAM>
    void Serialize(const secp256k1_context* ctx, STREAM& stream) const
    {
        FrostMessage::Serialize(stream);
        stream.write(share.data, sizeof(share.data));
    }

    template <typename STREAM>
    void Unserialize(const secp256k1_context* ctx, STREAM& stream)
    {
        FrostMessage::Unserialize(stream);

        if (sizeof(share.data) > stream.remains()) {
            std::stringstream hexstr;
            hexstr << hex(stream);
            throw UnserializeError(hexstr.str());
        }

        stream.read(share.data, sizeof(share.data));
    }

    std::string ToString() const override
    {
        std::stringstream buf;
        buf << "KeyShare {pk: " << hex(pubkey).substr(0, 8) << "... " << hex(share.data) << '}';
        return move(buf.str());
    }

private:
    KeyShare() : FrostMessage(), share{} {}

    template<typename STREAM>
    friend frost_message_ptr Unserialize(const secp256k1_context* ctx, STREAM& stream);
};

class SignatureCommitment : public FrostMessage
{
public:
    uint32_t operation_id;
    SignatureCommitment(xonly_pubkey&& pk, uint32_t opid) noexcept : FrostMessage(FROST_MESSAGE::SIGNATURE_COMMITMENT, move(pk)), operation_id(opid) {}
    SignatureCommitment(SignatureCommitment&& r) noexcept : FrostMessage(move(r)), operation_id(r.operation_id) {}

    template <typename STREAM>
    void Serialize(const secp256k1_context* ctx, STREAM& stream) const
    {
        FrostMessage::Serialize(stream);
        stream << operation_id;
    }

    template <typename STREAM>
    void Unserialize(const secp256k1_context* ctx, STREAM& stream)
    {
        FrostMessage::Unserialize(stream);
        stream >> operation_id;
    }

    std::string ToString() const override
    {
        std::stringstream buf;
        buf << "SignatureCommitment {pk: " << hex(pubkey).substr(0, 8) << "...}";
        return move(buf.str());
    }

private:
    SignatureCommitment() : FrostMessage(), operation_id(0) {}

    template<typename STREAM>
    friend frost_message_ptr Unserialize(const secp256k1_context* ctx, STREAM& stream);
};

class SignatureShare : public FrostMessage
{
public:
    uint32_t operation_id;
    frost_sigshare share;

    SignatureShare(xonly_pubkey&& pk, uint32_t opid) noexcept : FrostMessage(FROST_MESSAGE::SIGNATURE_SHARE, move(pk)), operation_id(opid), share{} {}
    SignatureShare(SignatureShare&& r) noexcept : FrostMessage(move(r)), operation_id(r.operation_id), share(move(r.share)) {}

    template <typename STREAM>
    void Serialize(const secp256k1_context* ctx, STREAM& stream) const
    {
        FrostMessage::Serialize(stream);
        stream << operation_id << share;
    }

    template <typename STREAM>
    void Unserialize(const secp256k1_context* ctx, STREAM& stream)
    {
        FrostMessage::Unserialize(stream);

        if ((sizeof(operation_id) + share.size()) > stream.remains()) {
            std::stringstream hexstr;
            hexstr << hex(stream);
            throw UnserializeError(hexstr.str());
        }

        stream >> operation_id >> share;
    }

    std::string ToString() const override
    {
        std::stringstream buf;
        buf << "SignatureShare {pk: " << hex(pubkey).substr(0, 8) << "... " << hex(share) << '}';
        return move(buf.str());
    }

private:
    SignatureShare() : FrostMessage(), operation_id(0), share() {}

    template<typename STREAM>
    friend frost_message_ptr Unserialize(const secp256k1_context* ctx, STREAM& stream);
};

template <typename STREAM>
void Serialize(STREAM& stream, const secp256k1_context* ctx, const FrostMessage& m)
{
    switch (m.id) {
    case FROST_MESSAGE::NONCE_COMMITMENTS:
    {
        const NonceCommitments& msg = dynamic_cast<const NonceCommitments&>(m);
        msg.Serialize(ctx, stream);
        return;
    }
    case FROST_MESSAGE::KEY_COMMITMENT:
    {
        const KeyShareCommitment& msg = dynamic_cast<const KeyShareCommitment&>(m);
        msg.Serialize(ctx, stream);
        return;
    }
    case FROST_MESSAGE::KEY_SHARE:
    {
        const KeyShare& msg = dynamic_cast<const KeyShare&>(m);
        msg.Serialize(ctx, stream);
        return;
    }
    case FROST_MESSAGE::SIGNATURE_COMMITMENT:
    {
        const SignatureCommitment& msg = dynamic_cast<const SignatureCommitment&>(m);
        msg.Serialize(ctx, stream);
        return;
    }
    case FROST_MESSAGE::SIGNATURE_SHARE:
    {
        const SignatureShare& msg = dynamic_cast<const SignatureShare&>(m);
        msg.Serialize(ctx, stream);
        return;
    }
    default:
        throw WrongMessage(m);
    }
}

template<typename STREAM>
frost_message_ptr Unserialize(const secp256k1_context* ctx, STREAM& stream)
{
    FrostMessage header;
    auto pos = stream.position();
    header.Unserialize(stream);
    stream.rewind(stream.position() - pos);

    switch (header.id) {
    case FROST_MESSAGE::NONCE_COMMITMENTS:
        {
            NonceCommitments msg;
            msg.Unserialize(ctx, stream);
            return std::make_unique<NonceCommitments>(move(msg));
        }
    case FROST_MESSAGE::KEY_COMMITMENT:
        {
            KeyShareCommitment msg;
            msg.Unserialize(ctx, stream);
            return std::make_unique<KeyShareCommitment>(move(msg));
        }
    case FROST_MESSAGE::KEY_SHARE:
        {
            KeyShare msg;
            msg.Unserialize(ctx, stream);
            return std::make_unique<KeyShare>(move(msg));
        }
    case FROST_MESSAGE::SIGNATURE_COMMITMENT:
        {
            SignatureCommitment msg;
            msg.Unserialize(ctx, stream);
            return std::make_unique<SignatureCommitment>(move(msg));
        }
    case FROST_MESSAGE::SIGNATURE_SHARE:
        {
            SignatureShare msg;
            msg.Unserialize(ctx, stream);
            return std::make_unique<SignatureShare>(move(msg));
        }
    default:
        throw WrongMessage(header);
    }
}


}
