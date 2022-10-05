#include "signer_api.hpp"

#include <utility>
#include <sstream>

#include "smartinserter.hpp"

#include "util/strencodings.h"

#include "secp256k1_schnorrsig.h"


namespace l15::core {

using namespace p2p;

SignerApi::SignerApi(ChannelKeys &&keypair,
                     size_t cluster_size,
                     size_t threshold_size,
                     new_sigop_handler sigop,
                     aggregate_sig_handler aggsig,
                     error_handler e)

    : m_ctx(keypair.Secp256k1Context())
    , mKeypair(keypair)
    , mKeyShare(m_ctx)
    , m_nonce_count(0)
    , m_threshold_size(threshold_size)
    , m_peers_data(cluster_size)
    , m_keyshare_count(0)
    , m_vss_hash()
    , m_secnonces()
    , mHandlers()
    , m_new_sig_handler(std::move(sigop))
    , m_aggregate_sig_handler(std::move(aggsig))
    , m_err_handler(std::move(e))
{
    mHandlers[(size_t)FROST_MESSAGE::NONCE_COMMITMENTS] = &SignerApi::AcceptNonceCommitments;
    mHandlers[(size_t)FROST_MESSAGE::KEY_COMMITMENT] = &SignerApi::AcceptKeyShareCommitment;
    mHandlers[(size_t)FROST_MESSAGE::KEY_SHARE] = &SignerApi::AcceptKeyShare;
    mHandlers[(size_t)FROST_MESSAGE::SIGNATURE_COMMITMENT] = &SignerApi::AcceptSignatureCommitment;
    mHandlers[(size_t)FROST_MESSAGE::SIGNATURE_SHARE] = &SignerApi::AcceptSignatureShare;

    AddPeer(xonly_pubkey(mKeypair.GetLocalPubKey()), nullptr);
}

void SignerApi::Accept(const Message& m)
{
    if (m.protocol_id != (uint16_t)PROTOCOL::FROST) {
        m_err_handler(WrongProtocol(m.protocol_id));
    }

    if (m.id < (size_t)FROST_MESSAGE::MESSAGE_ID_COUNT) {
        (this->*mHandlers[m.id])(m);
    }
    else {
        m_err_handler(WrongMessage(m));
    }
}


void SignerApi::AcceptNonceCommitments(const Message &m)
{
    const auto& message = reinterpret_cast<const NonceCommitments&>(m);

    if (m_peers_data.contains(message.pubkey)) {
        auto& ephemeral_pubkeys = m_peers_data[message.pubkey].ephemeral_pubkeys;
        ephemeral_pubkeys.insert(ephemeral_pubkeys.end(), message.nonce_commitments.begin(),
                                 message.nonce_commitments.end());
    }
    else {
        m_err_handler(WrongMessageData(m));
    }
}

void SignerApi::AcceptKeyShareCommitment(const Message &m)
{
    const auto& message = reinterpret_cast<const KeyShareCommitment&>(m);

    auto peer_it = m_peers_data.find(message.pubkey);
    if (peer_it != m_peers_data.end()
        && peer_it->second.keyshare_commitment.empty())
    {
        peer_it->second.keyshare_commitment = message.share_commitment;
    }
    else {
        m_err_handler(WrongMessageData(m));
    }
}

void SignerApi::AcceptKeyShare(const Message &m)
{
    const auto& message = reinterpret_cast<const KeyShare&>(m);

    auto peer_it = m_peers_data.find(message.pubkey);
    if (peer_it != m_peers_data.end()
        && !peer_it->second.keyshare_commitment.empty()
        && !peer_it->second.keyshare.has_value())
    {

        peer_it->second.keyshare = message.share;

        if (++m_keyshare_count >= m_peers_data.size()) {
            m_key_handler(*this);
        }
    }
    else {
        m_err_handler(WrongMessageData(m));
    }
}

void SignerApi::AcceptSignatureCommitment(const p2p::Message& m)
{
    const auto& message = reinterpret_cast<const SignatureCommitment&>(m);

    auto peer_it = m_peers_data.find(message.pubkey);
    if (peer_it != m_peers_data.end()
        && mKeyShare.IsAssigned())
    {
        secp256k1_xonly_pubkey peer_pk = message.pubkey.get(m_ctx);

        [[maybe_unused]] const std::lock_guard<std::mutex> lock(m_sig_share_mutex);

        if (m_sigops_cache.find(message.operation_id) == m_sigops_cache.end()) {
            sigop_cache peers_cache {{}, sigshare_peers_cache(m_threshold_size), 0};
            get<1>(peers_cache).emplace(move(peer_pk), sigshare_cache());
            m_sigops_cache.emplace(message.operation_id, move(peers_cache));
        }
        else {
            get<1>(m_sigops_cache[message.operation_id]).emplace(move(peer_pk), sigshare_cache());
        }

    }

    if (std::get<1>(m_sigops_cache[message.operation_id]).size() >= m_threshold_size) {
        m_new_sig_handler(*this, message.operation_id);
    }
}

void SignerApi::AcceptSignatureShare(const Message &m)
{
    const auto& message = reinterpret_cast<const SignatureShare&>(m);

    auto peer_it = m_peers_data.find(message.pubkey);
    if (peer_it != m_peers_data.end()
        && mKeyShare.IsAssigned())
    {
        sigops_cache::iterator op_it;
        {
            [[maybe_unused]] const std::lock_guard<std::mutex> lock(m_sig_share_mutex);

            op_it = m_sigops_cache.find(message.operation_id);
            if (op_it == m_sigops_cache.end()) {
                m_err_handler(SignatureError((std::stringstream("Signing operation not found: ")<< message.operation_id).str()));
                return;

            }
            auto peer_cache_it = SigOpCachedPeers(op_it).find(message.pubkey.get(m_ctx));

            if (peer_cache_it != SigOpCachedPeers(op_it).end() || !peer_cache_it->second.has_value()) {
                peer_cache_it->second = message.share;
                ++SigOpSigShareCount(op_it);
            }
            else {
                std::stringstream errbuf("Peer is already provided its sig share: ");
                errbuf << message.operation_id;
                errbuf << '/';
                errbuf << HexStr(message.pubkey);
                m_err_handler(SignatureError(errbuf.str()));
                return;
            }
        }

        if (SigOpSigShareCount(op_it) == m_threshold_size) {
            m_aggregate_sig_handler(*this, message.operation_id);
        }
    }
    else {
        m_err_handler(WrongMessageData(m));
    }
}


void SignerApi::CommitNonces(size_t count)
{

    m_secnonces.resize(m_nonce_count);
    m_peers_data[mKeypair.GetPubKey()].ephemeral_pubkeys.resize(m_nonce_count);

    NonceCommitments message(xonly_pubkey(mKeypair.GetPubKey()));
    message.nonce_commitments.reserve(count);

    for (size_t i = 0; i < count; ++i) {
        seckey session_key = mKeypair.GetStrongRandomKey();
        secp256k1_frost_secnonce secnonce;
        secp256k1_frost_pubnonce pubnonce;

        if (!secp256k1_frost_nonce_gen(m_ctx, &secnonce, &pubnonce, session_key.data(), nullptr, nullptr, nullptr, nullptr)) {
            throw SignatureError("Pubnonce generation error");
        }

        m_secnonces.emplace_back(secnonce);
        message.nonce_commitments.emplace_back(pubnonce);
    }

    Publish(message);

    m_nonce_count += count;
}

void SignerApi::DistributeKeyShares(general_handler key_shares_received_handler)
{
    m_key_handler = move(key_shares_received_handler);

    seckey session;
    GetStrongRandBytes(session);

    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(m_ctx, &keypair, mKeypair.GetLocalPrivKey().data())) {
        throw WrongKeyError();
    }

    //TODO: Optimization is needed by parallelisation (but only when secp256k1_frost is optimized at commitment generation)

    secp256k1_frost_share tmp_share;
    KeyShareCommitment message(xonly_pubkey(mKeypair.GetPubKey()));
    message.share_commitment.resize(m_threshold_size);

    secp256k1_xonly_pubkey thispk = mKeypair.GetPubKey().get(m_ctx);

    if (!secp256k1_frost_share_gen(m_ctx,
                                   message.share_commitment.data(), &(tmp_share),
                                   session.data(), &keypair, &thispk, m_threshold_size)) {
        throw SignatureError("FROST share generation error");
    }

    Publish(message);

    SendToPeers<KeyShare>([&](KeyShare& m, const xonly_pubkey& remote_pk, const RemoteSignerData& s){
        secp256k1_xonly_pubkey pk = remote_pk.get(m_ctx);
        if (!secp256k1_frost_share_gen(m_ctx,
                                       nullptr, &(m.share),
                                       session.data(), &keypair, &pk, m_threshold_size)) {
            throw SignatureError("");
        }
    });

}

void SignerApi::AggregateKey()
{
    std::vector<const secp256k1_frost_share*> shares; shares.reserve(m_peers_data.size());
    std::vector<const secp256k1_pubkey*> commitments; commitments.reserve(m_peers_data.size());

    std::for_each(std::execution::seq, m_peers_data.cbegin(), m_peers_data.cend(), [&](const auto& s)
    {
        if (!s.second.keyshare.has_value()) {
            throw KeyAggregationError();
        }
        shares.emplace_back(&s.second.keyshare.value());
        commitments.emplace_back(s.second.keyshare_commitment.data());

    });

    secp256k1_xonly_pubkey signer_pk = GetLocalPubKey().get(m_ctx);

    std::for_each(std::execution::par_unseq, m_peers_data.begin(), m_peers_data.end(), [&](auto & s)
    {
        secp256k1_pubkey* commitment = s.second.keyshare_commitment.data();
        if (!secp256k1_frost_share_verify(m_ctx, m_threshold_size, &signer_pk,
                                          &s.second.keyshare.value(), &(commitment))) {
            throw KeyShareVerificationError();
        }
    });

    secp256k1_frost_share agg_share;
    secp256k1_xonly_pubkey agg_pk;

    if (!secp256k1_frost_share_agg(m_ctx,
                                   &agg_share, &agg_pk,
                                   m_vss_hash.data(),
                                   shares.data(), commitments.data(),
                                   m_peers_data.size(), m_threshold_size,
                                   &signer_pk)) {

        throw KeyAggregationError();
    }

    std::for_each(std::execution::par_unseq, m_peers_data.begin(), m_peers_data.end(), [](auto & s)
    {
        s.second.keyshare_commitment.clear();
        s.second.keyshare.reset();
    });

    seckey share;
    std::copy(agg_share.data, agg_share.data + sizeof(agg_share.data), share.begin());

    xonly_pubkey agg_pubkey;
    agg_pubkey.set(m_ctx, agg_pk);

    mKeyShare = ChannelKeys(m_ctx, std::move(share));
    mKeyShare.SetAggregatePubKey(std::move(agg_pubkey));
}

signature SignerApi::AggregateSignature(operation_id opid)
{
    signature sig_agg;
    std::vector<secp256k1_frost_partial_sig> sigshares_data(m_threshold_size);
    std::vector<secp256k1_frost_partial_sig *> sigshares(m_threshold_size);
    auto op_it = m_sigops_cache.find(opid);

    std::transform(std::execution::par_unseq, SigOpCachedPeers(op_it).begin(), SigOpCachedPeers(op_it).end(), sigshares_data.begin(), [&](const auto& s)
    {
        secp256k1_frost_partial_sig share;
        secp256k1_frost_partial_sig_parse(m_ctx, &share, s.second->data());
        return share;
    });
    std::transform(std::execution::par_unseq, sigshares_data.begin(), sigshares_data.end(), sigshares.begin(), [](secp256k1_frost_partial_sig& s) { return &s; });

    if (!secp256k1_frost_partial_sig_agg(m_ctx, sig_agg.data(), &(SigOpSession(op_it).value()), sigshares.data(), m_threshold_size)) {
        throw SignatureError("Signature aggregation error");
    }
    else {
        return sig_agg;
    }
}

void SignerApi::InitSignature(operation_id opid, bool participate)
{
    if (participate) {
        SignatureCommitment message(xonly_pubkey(mKeypair.GetLocalPubKey()), opid);
        Publish(message);
    }
}

void SignerApi::PreprocessSignature(const uint256 &datahash, operation_id opid)
{
    auto op_it = m_sigops_cache.find(opid);

    const auto& sigshares = SigOpCachedPeers(op_it);

    if (sigshares.size() < m_threshold_size) {
        throw SignatureError((stringstream("Not enough participants: ") << sigshares.size()).str());
    }

    SigOpSession(op_it).emplace(secp256k1_frost_session());
    secp256k1_frost_session* session = &(SigOpSession(op_it).value());

    std::vector<const secp256k1_frost_pubnonce*> pubnonces; pubnonces.reserve(m_threshold_size);
    std::vector<const secp256k1_xonly_pubkey*> pubkeys; pubkeys.reserve(m_threshold_size);

    std::mutex m;
    std::for_each(std::execution::par_unseq, sigshares.begin(), sigshares.end(), [&](const auto& ss)
    {
        xonly_pubkey peer_pk(m_ctx, ss.first);
        const RemoteSignerData& peer = m_peers_data[peer_pk];
        auto I = peer.ephemeral_pubkeys.begin();
        std::advance(I, opid);

        {
            [[maybe_unused]] const std::lock_guard<std::mutex> lock(m);

            pubnonces.emplace_back(&(*I));
            pubkeys.emplace_back(&(ss.first));
        }
    });

    secp256k1_xonly_pubkey pubkey_agg = mKeyShare.GetPubKey().get(m_ctx);

    secp256k1_xonly_pubkey pubkey = mKeypair.GetLocalPubKey().get(m_ctx);

    if (!secp256k1_frost_nonce_process(m_ctx, session, pubnonces.data(), m_threshold_size,
                                       datahash.data(), &pubkey_agg, &pubkey, pubkeys.data(), nullptr, nullptr)) {
        throw SignatureError("FROST Nonce processing error");
    }

}

void SignerApi::DistributeSigShares(operation_id opid)
{
    auto op_it = m_sigops_cache.find(opid);

    if (!SigOpSession(op_it).has_value()) {
        throw SignatureError((std::stringstream("Signature operation is not found: ") << opid).str());
    }

    secp256k1_frost_session* session = &(SigOpSession(op_it).value());;

    auto secnonce_it = m_secnonces.begin();
    std::advance(secnonce_it, opid);

    secp256k1_frost_share keyshare;
    std::copy(mKeyShare.GetLocalPrivKey().begin(), mKeyShare.GetLocalPrivKey().end(), keyshare.data);

    secp256k1_frost_partial_sig sigshare;
    if (!secp256k1_frost_partial_sign(m_ctx, &sigshare, &*secnonce_it, &keyshare, session, nullptr)) {
        throw SignatureError("Signing error");
    }

    SignatureShare message(xonly_pubkey(mKeypair.GetPubKey()), opid);
    secp256k1_frost_partial_sig_serialize(m_ctx, message.share.data(), &sigshare);

    Publish(message);
}

void SignerApi::Verify(const uint256 &message, const signature &signature)
{
    secp256k1_xonly_pubkey pubkey = mKeyShare.GetPubKey().get(m_ctx);

    if (!secp256k1_schnorrsig_verify(m_ctx, signature.data(), message.data(), 32, &pubkey)) {
        throw SignatureError("Signature does not match");
    }

}

void SignerApi::ClearSignatureCache(operation_id opid)
{
    m_sigops_cache.erase(opid);
}

} // l15