#include "signer_api.hpp"

#include <utility>

#include "smartinserter.hpp"
#include "secp256k1_schnorrsig.h"


namespace l15 {

namespace {
    const unsigned char secp256k1_frost_partial_sig_magic[4] = { 0xeb, 0xfb, 0x1a, 0x32 };
}

using namespace p2p;

SignerApi::SignerApi(api::WalletApi& wallet,
                     size_t index,
                     ChannelKeys &&keypair,
                     size_t cluster_size,
                     size_t threshold_size,
                     new_sigop_handler sigop,
                     aggregate_sig_handler aggsig,
                     error_handler e)

    : mWallet(wallet)
    , mKeypair(keypair)
    , mKeyShare(wallet)
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

    if(message.peer_index < m_peers_data.size() && ChannelKeys::IsZeroArray(m_peers_data[message.peer_index].pubkey))
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

    if (message.peer_index < m_peers_data.size() && !ChannelKeys::IsZeroArray(m_peers_data[message.peer_index].pubkey)) {
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

    if (message.peer_index < m_peers_data.size() && !ChannelKeys::IsZeroArray(m_peers_data[message.peer_index].pubkey)
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

    if (message.peer_index < m_peers_data.size() && !ChannelKeys::IsZeroArray(m_peers_data[message.peer_index].pubkey)
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

    if (message.peer_index < m_peers_data.size() && !ChannelKeys::IsZeroArray(m_peers_data[message.peer_index].pubkey)
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

    if (message.peer_index < m_peers_data.size() && !ChannelKeys::IsZeroArray(m_peers_data[message.peer_index].pubkey)
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

    RemoteSigner message((uint32_t)m_signer_index, mKeypair.GetLocalPubKey());
    SendToPeers(message);
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

        if(!secp256k1_frost_nonce_gen(mWallet.GetSecp256k1Context(), &secnonce, &pubnonce, session_key.data(), nullptr, nullptr, nullptr, nullptr))
        {
            throw SignatureError();
        }

        frost_secnonce secnonce_bytes;
        frost_pubnonce pubnonce_bytes;

        std::copy(secnonce.data, secnonce.data + sizeof(secnonce.data), secnonce_bytes.begin());
        std::copy(pubnonce.data, pubnonce.data + sizeof(pubnonce.data), pubnonce_bytes.begin());

        m_secnonces.emplace_back(secnonce_bytes);
        //m_peers_data[m_signer_index].ephemeral_pubkeys.emplace_back(pubnonce_bytes);

        message.nonce_commitments.push_back(pubnonce_bytes);
    }

    SendToPeers(message);

    m_nonce_count += count;
}

void SignerApi::DistributeKeyShares()
{
    seckey session;
    GetStrongRandBytes(session);

    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(mWallet.GetSecp256k1Context(), &keypair, mKeypair.GetLocalPrivKey().data())) {
        throw WrongKeyError();
    }

    //TODO: Optimization is needed by parallelisation (but only when secp256k1_frost is optimized at commitment generation)

    std::vector<secp256k1_frost_share> shares(m_peers_data.size());
    std::vector<secp256k1_pubkey> share_commitment(m_threshold_size);
    KeyShareCommitment message(m_signer_index);

    size_t peer_count = m_peers_data.size();
    for (size_t i = 0; i < peer_count; ++i) {
        secp256k1_xonly_pubkey index_pubkey;
        if (!secp256k1_xonly_pubkey_parse(mWallet.GetSecp256k1Context(), &index_pubkey, m_peers_data[i].pubkey.data())) {
            throw WrongKeyError();
        }

        if (!secp256k1_frost_share_gen(mWallet.GetSecp256k1Context(),
                                       (i == 0) ? share_commitment.data() : nullptr, &(shares[i]),
                                       session.data(), &keypair, &index_pubkey, m_threshold_size)) {
            throw SignatureError();
        }
    }

    message.share_commitment.resize(share_commitment.size());
    std::transform(std::execution::par_unseq, share_commitment.cbegin(), share_commitment.cend(), message.share_commitment.begin(),
                   [&](const secp256k1_pubkey& pk) {
                       compressed_pubkey pk_out;
                       size_t out_len = pk_out.size();
                       secp256k1_ec_pubkey_serialize(mWallet.GetSecp256k1Context(), pk_out.data(), &out_len, &pk, SECP256K1_EC_COMPRESSED);
                       return pk_out;
                   } );

    SendToPeers(message);

    SendToPeers<KeyShare>([&](KeyShare& m, size_t i){
        std::copy(shares[i].data, shares[i].data + sizeof(shares[i].data), m.share.begin());
    });

}

void SignerApi::AggregateKey()
{
    std::vector<secp256k1_frost_share> shares_data(m_peers_data.size());
    std::vector<secp256k1_frost_share*> shares(m_peers_data.size());

    std::vector<std::vector<secp256k1_pubkey>> commitments_data(m_peers_data.size());
    std::vector<secp256k1_pubkey*> commitments(m_peers_data.size());

    std::for_each(std::execution::par_unseq, m_peers_data.cbegin(), m_peers_data.cend(), [&](const RemoteSignerData& s) {
        size_t i = &s - &(m_peers_data.front());

        if (!s.keyshare.has_value() || ChannelKeys::IsZeroArray(*s.keyshare)) {
            throw KeyAggregationError();
        }
        std::copy(s.keyshare->cbegin(), s.keyshare->cend(), shares_data[i].data);
        shares[i] = &shares_data[i];

        commitments_data[i].reserve(m_threshold_size);
        std::transform(s.keyshare_commitment.begin(), s.keyshare_commitment.end(),
                       cex::smartinserter(commitments_data[i], commitments_data[i].end()),
                       [&](const compressed_pubkey& p) {
            secp256k1_pubkey commit;
            if (!secp256k1_ec_pubkey_parse(mWallet.GetSecp256k1Context(), &commit, p.data(), p.size())) {
                throw KeyAggregationError();
            }
            return commit;
        } );
        commitments[i] = commitments_data[i].data();

    } );

    secp256k1_xonly_pubkey signer_pk;
    secp256k1_frost_share agg_share;
    secp256k1_xonly_pubkey agg_pk;
    secp256k1_pubkey share_pk;

    if (!secp256k1_xonly_pubkey_parse(mWallet.GetSecp256k1Context(), &signer_pk, m_peers_data[m_signer_index].pubkey.data())) {
        throw WrongKeyError();
    }

    if (!secp256k1_frost_share_agg(mWallet.GetSecp256k1Context(),
                                   &agg_share, &share_pk, &agg_pk,
                                   m_vss_hash.data(),
                                   shares.data(), commitments.data(),
                                   m_peers_data.size(), m_threshold_size,
                                   &signer_pk)) {

        throw KeyAggregationError();
    }

    std::for_each(m_peers_data.begin(), m_peers_data.end(), [](auto & s)
    {
        s.keyshare_commitment.clear();
        s.keyshare.reset();
    });

    seckey share;
    std::copy(agg_share.data, agg_share.data + sizeof(agg_share.data), share.begin());

    xonly_pubkey agg_pubkey;
    secp256k1_xonly_pubkey_serialize(mWallet.GetSecp256k1Context(), agg_pubkey.data(), &agg_pk);

    mKeyShare = ChannelKeys(mWallet, std::move(share));
    mKeyShare.SetAggregatePubKey(agg_pubkey);
}

signature SignerApi::AggregateSignature(operation_id opid)
{
    signature sig_agg;
    std::vector<secp256k1_frost_partial_sig> sigshares_data(m_threshold_size);
    std::vector<secp256k1_frost_partial_sig *> sigshares(m_threshold_size);

    std::transform(std::execution::par_unseq, SigOpCachedPeers(opid).begin(), SigOpCachedPeers(opid).end(), sigshares_data.begin(), [&](const auto& s)
    {
        //TODO: Remove init magics when secp256k1_frost_partial_sig_parse is fixed
        secp256k1_frost_partial_sig share {{0xeb, 0xfb, 0x1a, 0x32}};
        secp256k1_frost_partial_sig_parse(mWallet.GetSecp256k1Context(), &share, s.second->data());
        return share;
    });
    std::transform(std::execution::par_unseq, sigshares_data.begin(), sigshares_data.end(), sigshares.begin(), [](secp256k1_frost_partial_sig& s) { return &s; });

    if (!secp256k1_frost_partial_sig_agg(mWallet.GetSecp256k1Context(), sig_agg.data(), &(SigOpSession(opid).value()), sigshares.data(), m_threshold_size)) {
        throw SignatureError();
    }
    else {
        return sig_agg;
    }
}

void SignerApi::InitSignature(operation_id opid)
{
    SigOpSigShareCount(opid) = 0;

    SignatureCommitment message(m_signer_index, opid);
    SendToPeers(message);
}

void SignerApi::PreprocessSignature(const uint256 &datahash, operation_id opid)
{
    SigOpSession(opid).emplace(secp256k1_frost_session());
    secp256k1_frost_session* session = &(SigOpSession(opid).value());

    std::vector<std::pair<secp256k1_frost_pubnonce, secp256k1_xonly_pubkey>> data(m_threshold_size);

    std::vector<secp256k1_frost_pubnonce*> pubnonces(m_threshold_size);
    std::vector<secp256k1_xonly_pubkey*> pubkeys(m_threshold_size);

    const auto& peers = SigOpCachedPeers(opid);
    std::transform(std::execution::par_unseq, peers.cbegin(), peers.cend(), data.begin(), [&](const auto& ss)
    //for(auto it = peers.cbegin(); it != peers.cend(); ++it)
    {
        std::pair<secp256k1_frost_pubnonce, secp256k1_xonly_pubkey> item;
        const RemoteSignerData& peer = m_peers_data[ss.first];
        //const size_t index = peers.index_of(it);

        auto I = peer.ephemeral_pubkeys.begin();
        std::advance(I, opid);
        std::copy(I->data(), I->data() + I->size(), item.first.data);

        if (!secp256k1_xonly_pubkey_parse(mWallet.GetSecp256k1Context(), &item.second, peer.pubkey.data())) {
            throw WrongKeyError();
        }

        return item;
    });

    std::for_each(std::execution::par_unseq, data.begin(), data.end(), [&](auto& d){
        size_t index = &d - &data.front();
        pubnonces[index] = &d.first;
        pubkeys[index] = &d.second;
    });

    secp256k1_xonly_pubkey pubkey_agg;
    if (!secp256k1_xonly_pubkey_parse(mWallet.GetSecp256k1Context(), &pubkey_agg, mKeyShare.GetPubKey().data())) {
        throw WrongKeyError();
    }

    secp256k1_xonly_pubkey pubkey;
    if (!secp256k1_xonly_pubkey_parse(mWallet.GetSecp256k1Context(), &pubkey, mKeypair.GetLocalPubKey().data())) {
        throw WrongKeyError();
    }

    if (!secp256k1_frost_nonce_process(mWallet.GetSecp256k1Context(), session, pubnonces.data(), m_threshold_size,
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

    secp256k1_frost_secnonce secnonce;
    auto secnonce_it = m_secnonces.begin();
    std::advance(secnonce_it, opid);
    std::copy(secnonce_it->begin(), secnonce_it->end(), secnonce.data);

    secp256k1_frost_share keyshare;
    std::copy(mKeyShare.GetLocalPrivKey().begin(), mKeyShare.GetLocalPrivKey().end(), keyshare.data);

    secp256k1_frost_partial_sig sigshare;
    if (!secp256k1_frost_partial_sign(mWallet.GetSecp256k1Context(), &sigshare, &secnonce, &keyshare, session, nullptr)) {
        throw SignatureError();
    }

    SignatureShare message(m_signer_index, opid);
    secp256k1_frost_partial_sig_serialize(mWallet.GetSecp256k1Context(), message.share.data(), &sigshare);

    SendToPeers(message);
}

void SignerApi::Verify(const uint256 &message, const signature &signature)
{
    secp256k1_xonly_pubkey pubkey;

    if (!secp256k1_xonly_pubkey_parse(mWallet.GetSecp256k1Context(), &pubkey, mKeyShare.GetPubKey().data())) {
        throw WrongKeyError();
    }

    if (!secp256k1_schnorrsig_verify(mWallet.GetSecp256k1Context(), signature.data(), message.data(), 32, &pubkey)) {
        throw SignatureError();
    }

}

void SignerApi::ClearSignatureCache(l15::operation_id opid)
{
    m_sigops_cache.erase(opid);
}

} // l15