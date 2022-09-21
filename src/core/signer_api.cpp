#include "signer_api.hpp"

#include <utility>

#include "smartinserter.hpp"
#include "secp256k1_schnorrsig.h"


namespace l15::core {

using namespace p2p;

SignerApi::SignerApi(size_t index,
                     ChannelKeys &&keypair,
                     size_t cluster_size,
                     size_t threshold_size,
                     new_sigop_handler sigop,
                     aggregate_sig_handler aggsig,
                     error_handler e)

    : m_ctx(keypair.Secp256k1Context())
    , mKeypair(keypair)
    , mKeyShare(m_ctx)
    , m_signer_index(index)
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
    mHandlers[(size_t)FROST_MESSAGE::REMOTE_SIGNER] = &SignerApi::AcceptRemoteSigner;
    mHandlers[(size_t)FROST_MESSAGE::NONCE_COMMITMENTS] = &SignerApi::AcceptNonceCommitments;
    mHandlers[(size_t)FROST_MESSAGE::KEY_COMMITMENT] = &SignerApi::AcceptKeyShareCommitment;
    mHandlers[(size_t)FROST_MESSAGE::KEY_SHARE] = &SignerApi::AcceptKeyShare;
    mHandlers[(size_t)FROST_MESSAGE::SIGNATURE_COMMITMENT] = &SignerApi::AcceptSignatureCommitment;
    mHandlers[(size_t)FROST_MESSAGE::SIGNATURE_SHARE] = &SignerApi::AcceptSignatureShare;
}

void SignerApi::AddPeer(size_t index, link_ptr link)
{
    m_peers_data[index].link = std::move(link);
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

void SignerApi::AcceptRemoteSigner(const Message &m)
{
    const auto &message = reinterpret_cast<const RemoteSigner &>(m);

    if(message.peer_index < m_peers_data.size() /*&& ChannelKeys::IsZeroArray(m_peers_data[message.peer_index].pubkey.data)*/)
    {
        m_peers_data[message.peer_index].pubkey = message.pubkey;
    }
    else {
        m_err_handler(WrongMessageData(m));
    }
}

void SignerApi::AcceptNonceCommitments(const Message &m)
{
    const auto& message = reinterpret_cast<const NonceCommitments&>(m);

    if (message.peer_index < m_peers_data.size() /*&& !ChannelKeys::IsZeroArray(m_peers_data[message.peer_index].pubkey.data)*/) {
        auto& ephemeral_pubkeys = m_peers_data[message.peer_index].ephemeral_pubkeys;
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

    if (message.peer_index < m_peers_data.size()/* && !ChannelKeys::IsZeroArray(m_peers_data[message.peer_index].pubkey.data)*/
        && m_peers_data[message.peer_index].keyshare_commitment.empty()) {
        m_peers_data[message.peer_index].keyshare_commitment = message.share_commitment;
    }
    else {
        m_err_handler(WrongMessageData(m));
    }
}

void SignerApi::AcceptKeyShare(const Message &m)
{
    const auto& message = reinterpret_cast<const KeyShare&>(m);

    if (message.peer_index < m_peers_data.size()/* && !ChannelKeys::IsZeroArray(m_peers_data[message.peer_index].pubkey.data)*/
        && !m_peers_data[message.peer_index].keyshare_commitment.empty() && !m_peers_data[message.peer_index].keyshare.has_value()) {

        m_peers_data[message.peer_index].keyshare = message.share;

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

    if (message.peer_index < m_peers_data.size()/* && !ChannelKeys::IsZeroArray(m_peers_data[message.peer_index].pubkey.data)*/
        && mKeyShare.IsAssigned())
    {
        [[maybe_unused]] const std::lock_guard<std::mutex> lock(m_sig_share_mutex);

        if (m_sigops_cache.find(message.operation_id) == m_sigops_cache.end()) {
            std::get<1>(m_sigops_cache[message.operation_id]).reserve(m_threshold_size);
        }

        std::get<1>(m_sigops_cache[message.operation_id])[message.peer_index] = sigop_peer_cache();
    }

    if (std::get<1>(m_sigops_cache[message.operation_id]).size() >= m_threshold_size) {
        m_new_sig_handler(*this, message.operation_id);
    }
}

void SignerApi::AcceptSignatureShare(const Message &m)
{
    const auto& message = reinterpret_cast<const SignatureShare&>(m);

    if (message.peer_index < m_peers_data.size()/* && !ChannelKeys::IsZeroArray(m_peers_data[message.peer_index].pubkey.data)*/
        && mKeyShare.IsAssigned())
    {
        {
            [[maybe_unused]] const std::lock_guard<std::mutex> lock(m_sig_share_mutex);

            auto peer_cache_it = SigOpCachedPeers(message.operation_id).find(message.peer_index);

            if (peer_cache_it != SigOpCachedPeers(message.operation_id).end() || !peer_cache_it->second.has_value()) {
                peer_cache_it->second = message.share;
                ++SigOpSigShareCount(message.operation_id);
            }
            else {
                m_err_handler(SignatureError());
                return;
            }
        }

        //std::clog << "Sigshare(" << message.peer_index << "): " << HexStr(message.share) << std::endl;

        if (SigOpSigShareCount(message.operation_id) == m_threshold_size) {
            m_aggregate_sig_handler(*this, message.operation_id);
        }
    }
    else {
        m_err_handler(WrongMessageData(m));
    }
}

void SignerApi::RegisterToPeers(aggregate_key_handler handler)
{
    m_key_handler = std::move(handler);

    RemoteSigner message((uint32_t)m_signer_index);
    mKeypair.GetLocalPubKey().get(m_ctx, message.pubkey);

    Publish(message);
}

void SignerApi::CommitNonces(size_t count)
{

    m_secnonces.resize(m_nonce_count);
    m_peers_data[m_signer_index].ephemeral_pubkeys.resize(m_nonce_count);

    NonceCommitments message((uint32_t)m_signer_index);
    message.nonce_commitments.reserve(count);

    for(size_t i = 0; i < count; ++i) {
        seckey session_key = mKeypair.GetStrongRandomKey();
        secp256k1_frost_secnonce secnonce;
        secp256k1_frost_pubnonce pubnonce;

        if(!secp256k1_frost_nonce_gen(m_ctx, &secnonce, &pubnonce, session_key.data(), nullptr, nullptr, nullptr, nullptr))
        {
            throw SignatureError();
        }

        m_secnonces.emplace_back(secnonce);
        message.nonce_commitments.emplace_back(pubnonce);
    }

    Publish(message);

    m_nonce_count += count;
}

void SignerApi::DistributeKeyShares()
{
    seckey session;
    GetStrongRandBytes(session);

    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(m_ctx, &keypair, mKeypair.GetLocalPrivKey().data())) {
        throw WrongKeyError();
    }

    //TODO: Optimization is needed by parallelisation (but only when secp256k1_frost is optimized at commitment generation)

    secp256k1_frost_share tmp_share;
    KeyShareCommitment message(m_signer_index);
    message.share_commitment.resize(m_threshold_size);

    if (!secp256k1_frost_share_gen(m_ctx,
                                   message.share_commitment.data(), &(tmp_share),
                                   session.data(), &keypair, &m_peers_data[0].pubkey, m_threshold_size)) {
        throw SignatureError();
    }

    Publish(message);

    SendToPeers<KeyShare>([&](KeyShare& m, const RemoteSignerData& s, size_t i){
        if (!secp256k1_frost_share_gen(m_ctx,
                                       nullptr, &(m.share),
                                       session.data(), &keypair, &s.pubkey, m_threshold_size)) {
            throw SignatureError();
        }
    });

}

void SignerApi::AggregateKey()
{
    std::vector<const secp256k1_frost_share*> shares(m_peers_data.size());
    std::vector<const secp256k1_pubkey*> commitments(m_peers_data.size());

    std::for_each(std::execution::par_unseq, m_peers_data.cbegin(), m_peers_data.cend(), [&](const RemoteSignerData& s) {
        size_t i = &s - &(m_peers_data.front());

        if (!s.keyshare.has_value()) {
            throw KeyAggregationError();
        }
        shares[i] = &s.keyshare.value();
        commitments[i] = s.keyshare_commitment.data();

    } );

    secp256k1_xonly_pubkey signer_pk = GetLocalPubKey().get(m_ctx);

    std::for_each(std::execution::par_unseq, m_peers_data.begin(), m_peers_data.end(), [&](auto & s)
    {
        secp256k1_pubkey* commitment = s.keyshare_commitment.data();
        if (!secp256k1_frost_share_verify(m_ctx, m_threshold_size, &signer_pk,
                                          &s.keyshare.value(), &(commitment))) {
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
        s.keyshare_commitment.clear();
        s.keyshare.reset();
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

    std::transform(std::execution::par_unseq, SigOpCachedPeers(opid).begin(), SigOpCachedPeers(opid).end(), sigshares_data.begin(), [&](const auto& s)
    {
        secp256k1_frost_partial_sig share;
        secp256k1_frost_partial_sig_parse(m_ctx, &share, s.second->data());
        return share;
    });
    std::transform(std::execution::par_unseq, sigshares_data.begin(), sigshares_data.end(), sigshares.begin(), [](secp256k1_frost_partial_sig& s) { return &s; });

    if (!secp256k1_frost_partial_sig_agg(m_ctx, sig_agg.data(), &(SigOpSession(opid).value()), sigshares.data(), m_threshold_size)) {
        throw SignatureError();
    }
    else {
        return sig_agg;
    }
}

void SignerApi::InitSignature(operation_id opid, bool participate)
{
    SigOpSigShareCount(opid) = 0;

    if (participate) {
        SignatureCommitment message(m_signer_index, opid);
        Publish(message);
    }
}

void SignerApi::PreprocessSignature(const uint256 &datahash, operation_id opid)
{
    SigOpSession(opid).emplace(secp256k1_frost_session());
    secp256k1_frost_session* session = &(SigOpSession(opid).value());

    std::vector<const secp256k1_frost_pubnonce*> pubnonces(m_threshold_size);
    std::vector<const secp256k1_xonly_pubkey*> pubkeys(m_threshold_size);

    const auto& peers = SigOpCachedPeers(opid);

    std::transform(std::execution::par_unseq, peers.begin(), peers.end(), pubnonces.begin(), [&](const auto& ss)
    {
        const RemoteSignerData& peer = m_peers_data[ss.first];
        auto I = peer.ephemeral_pubkeys.begin();
        std::advance(I, opid);
        return &(*I);
    });

    std::transform(std::execution::par_unseq, peers.begin(), peers.end(), pubkeys.begin(), [&](const auto& ss)
    {
        const RemoteSignerData& peer = m_peers_data[ss.first];
        return &(peer.pubkey);
    });

    secp256k1_xonly_pubkey pubkey_agg = mKeyShare.GetPubKey().get(m_ctx);

    secp256k1_xonly_pubkey pubkey = mKeypair.GetLocalPubKey().get(m_ctx);

    if (!secp256k1_frost_nonce_process(m_ctx, session, pubnonces.data(), m_threshold_size,
                                       datahash.data(), &pubkey_agg, &pubkey, pubkeys.data(), nullptr, nullptr)) {
        throw SignatureError();
    }

}

void SignerApi::DistributeSigShares(operation_id opid)
{
    if (!SigOpSession(opid).has_value()) {
        throw SignatureError();
    }

    secp256k1_frost_session* session = &(SigOpSession(opid).value());;

    auto secnonce_it = m_secnonces.begin();
    std::advance(secnonce_it, opid);

    secp256k1_frost_share keyshare;
    std::copy(mKeyShare.GetLocalPrivKey().begin(), mKeyShare.GetLocalPrivKey().end(), keyshare.data);

    secp256k1_frost_partial_sig sigshare;
    if (!secp256k1_frost_partial_sign(m_ctx, &sigshare, &*secnonce_it, &keyshare, session, nullptr)) {
        throw SignatureError();
    }

    SignatureShare message(m_signer_index, opid);
    secp256k1_frost_partial_sig_serialize(m_ctx, message.share.data(), &sigshare);

    Publish(message);
}

void SignerApi::Verify(const uint256 &message, const signature &signature)
{
    secp256k1_xonly_pubkey pubkey = mKeyShare.GetPubKey().get(m_ctx);

    if (!secp256k1_schnorrsig_verify(m_ctx, signature.data(), message.data(), 32, &pubkey)) {
        throw SignatureError();
    }

}

void SignerApi::ClearSignatureCache(operation_id opid)
{
    m_sigops_cache.erase(opid);
}

} // l15