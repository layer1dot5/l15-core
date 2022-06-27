#include "signer_service.hpp"

#include <utility>

#include "cex/smartinserter.hpp"


namespace l15 {

using namespace p2p;

SignerService::SignerService(api::WalletApi& wallet, size_t index, ChannelKeys &&keypair, size_t cluster_size, size_t threshold_size)
: mWallet(wallet), mKeypair(keypair), mKeyShare(wallet), m_signer_index(index), m_nonce_count(0), m_operation_index(0), m_threshold_size(threshold_size)
, m_peers_data(cluster_size), m_keyshare_count(0), m_vss_hash()
{
    mHandlers[(size_t)FROST_MESSAGE::REMOTE_SIGNER] = &SignerService::AcceptRemoteSigner;
    mHandlers[(size_t)FROST_MESSAGE::NONCE_COMMITMENTS] = &SignerService::AcceptNonceCommitments;
    mHandlers[(size_t)FROST_MESSAGE::KEYSHARE_COMMITMENT] = &SignerService::AcceptKeyShareCommitment;
    mHandlers[(size_t)FROST_MESSAGE::KEYSHARE] = &SignerService::AcceptKeyShare;
}

void SignerService::AddPeer(size_t index, link_ptr link)
{
    m_peers_data[index].link = std::move(link);
}

void SignerService::Accept(const Message& m)
{
    if (m.protocol_id != (uint16_t)PROTOCOL::FROST) {
        throw WrongProtocol{m.protocol_id};
    }

    if (m.id < (size_t)FROST_MESSAGE::MESSAGE_ID_COUNT) {
        (this->*mHandlers[m.id])(m);
    }
    else {
        throw WrongMessage{m.protocol_id, m.id};
    }
}

void SignerService::AcceptRemoteSigner(const Message &m)
{
    const auto &message = reinterpret_cast<const RemoteSigner &>(m);

    if(message.index < m_peers_data.size() && ChannelKeys::IsZeroArray(m_peers_data[message.index].pubkey))
    {
        m_peers_data[message.index].pubkey = message.pubkey;
    }
    else {
        throw WrongMessageData{m.protocol_id, m.id};
    }
}

void SignerService::AcceptNonceCommitments(const Message &m)
{
    const auto& message = reinterpret_cast<const NonceCommitments&>(m);

    if (message.index < m_peers_data.size() && !ChannelKeys::IsZeroArray(m_peers_data[message.index].pubkey)) {
        auto& ephemeral_pubkeys = m_peers_data[message.index].ephemeral_pubkeys;
        ephemeral_pubkeys.insert(ephemeral_pubkeys.end(), message.nonce_commitments.begin(),
                                 message.nonce_commitments.end());
    }
    else {
        throw WrongMessageData{m.protocol_id, m.id};
    }
}

void SignerService::AcceptKeyShareCommitment(const Message &m)
{
    const auto& message = reinterpret_cast<const KeyShareCommitment&>(m);

    if (message.index < m_peers_data.size() && !ChannelKeys::IsZeroArray(m_peers_data[message.index].pubkey)
        && m_peers_data[message.index].share_commitment.empty()) {
        m_peers_data[message.index].share_commitment = message.share_commitment;
    }
    else {
        throw WrongMessageData{m.protocol_id, m.id};
    }
}

void SignerService::AcceptKeyShare(const Message &m)
{
    const auto& message = reinterpret_cast<const KeyShare&>(m);

    if (message.index < m_peers_data.size() && !ChannelKeys::IsZeroArray(m_peers_data[message.index].pubkey)
        && !m_peers_data[message.index].share_commitment.empty() && ChannelKeys::IsZeroArray(m_peers_data[message.index].share)) {


        m_peers_data[message.index].share = message.share;

        if (++m_keyshare_count >= m_peers_data.size()) {
            AggregateKeyShares();
        }
    }
    else {
        throw WrongMessageData{m.protocol_id, m.id};
    }

}

void SignerService::RegisterToPeers()
{
    RemoteSigner message((uint32_t)m_signer_index, mKeypair.GetLocalPubKey());
    SendToPeers(message);
}

void SignerService::CommitNonces(size_t count)
{

    m_secnonces.resize(m_nonce_count);
    m_peers_data[m_signer_index].ephemeral_pubkeys.resize(m_nonce_count);

    NonceCommitments message((uint32_t)m_signer_index);
    message.nonce_commitments.reserve(count);

    for(size_t i = 0; i < count; ++i) {
        seckey session_key = mKeypair.GetStrongRandomKey();
        secp256k1_frost_secnonce secnonce;
        secp256k1_frost_pubnonce pubnonce;

        if(!secp256k1_frost_nonce_gen(mWallet.GetSecp256k1Context(), &secnonce, &pubnonce, session_key.data(), NULL, NULL, NULL, NULL))
        {
            throw SignerError();
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

void SignerService::CommitKeyShares()
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
                                       (i == 0) ? share_commitment.data() : NULL, &(shares[i]),
                                       session.data(), &keypair, &index_pubkey, m_threshold_size)) {
            throw SignerError();
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

void SignerService::AggregateKeyShares()
{
    std::vector<secp256k1_frost_share> shares_data(m_peers_data.size());
    std::vector<secp256k1_frost_share*> shares(m_peers_data.size());

    std::vector<std::vector<secp256k1_pubkey>> commitments_data(m_peers_data.size());
    std::vector<secp256k1_pubkey*> commitments(m_peers_data.size());

    std::for_each(std::execution::par_unseq, m_peers_data.cbegin(), m_peers_data.cend(), [&](const RemoteSignerData& s) {
        size_t i = &s - &(m_peers_data.front());

        if (ChannelKeys::IsZeroArray(s.share)) {
            throw KeyAggregationError();
        }
        std::copy(s.share.cbegin(), s.share.cend(), shares_data[i].data);
        shares[i] = &shares_data[i];

        commitments_data[i].reserve(m_threshold_size);
        std::transform(s.share_commitment.begin(), s.share_commitment.end(),
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

    seckey share;
    std::copy(agg_share.data, agg_share.data + sizeof(agg_share.data), share.begin());

    xonly_pubkey agg_pubkey;
    secp256k1_xonly_pubkey_serialize(mWallet.GetSecp256k1Context(), agg_pubkey.data(), &agg_pk);

    mKeyShare = ChannelKeys(mWallet, std::move(share));
    mKeyShare.SetAggregatePubKey(agg_pubkey);
}


} // l15