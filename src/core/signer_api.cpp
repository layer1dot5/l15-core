#include "signer_api.hpp"

#include <utility>

#include "smartinserter.hpp"
#include "secp256k1_schnorrsig.h"


namespace l15 {

namespace {
    const unsigned char secp256k1_frost_partial_sig_magic[4] = { 0xeb, 0xfb, 0x1a, 0x32 };
}

using namespace p2p;

SignerApi::SignerApi(api::WalletApi& wallet, size_t index, ChannelKeys &&keypair, size_t cluster_size, size_t threshold_size, error_handler e)
: mWallet(wallet), mKeypair(keypair), mKeyShare(wallet), m_signer_index(index), m_nonce_count(0), m_opid(0), m_threshold_size(threshold_size)
, m_peers_data(cluster_size), m_keyshare_count(0), m_vss_hash(), m_err_handler(e)
{
    mHandlers[(size_t)FROST_MESSAGE::REMOTE_SIGNER] = &SignerApi::AcceptRemoteSigner;
    mHandlers[(size_t)FROST_MESSAGE::NONCE_COMMITMENTS] = &SignerApi::AcceptNonceCommitments;
    mHandlers[(size_t)FROST_MESSAGE::KEY_SHARE_COMMITMENT] = &SignerApi::AcceptKeyShareCommitment;
    mHandlers[(size_t)FROST_MESSAGE::KEY_SHARE] = &SignerApi::AcceptKeyShare;
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

        m_peers_data[message.peer_index].keyshare.emplace(std::move(message.share));

        if (++m_keyshare_count >= m_peers_data.size()) {
            m_key_handler(*this);
        }
    }
    else {
        m_err_handler(WrongMessageData(m));
    }
}

void SignerApi::AcceptSignatureShare(const Message &m)
{
    const auto& message = reinterpret_cast<const SignatureShare&>(m);

    if (message.peer_index < m_peers_data.size() && !ChannelKeys::IsZeroArray(m_peers_data[message.peer_index].pubkey)
        && mKeyShare.IsAssigned()
        && GetOpId() == message.operation_id)
    {
        {
            const std::lock_guard<std::mutex> lock(m_sig_share_mutex);
            m_sig_shares[message.operation_id][message.peer_index] = message.share;
        }

        //std::clog << "Sigshare(" << message.peer_index << "): " << HexStr(message.share) << std::endl;

        if (m_sig_shares[message.operation_id].size() == m_threshold_size) {
            std::get<1>(m_sig_handlers[message.operation_id])(*this);
        }
    }
    else {
        m_err_handler(WrongMessageData(m));
    }
}

void SignerApi::RegisterToPeers(aggregate_key_handler handler)
{
    m_key_handler = handler;

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

        if(!secp256k1_frost_nonce_gen(mWallet.GetSecp256k1Context(), &secnonce, &pubnonce, session_key.data(), NULL, NULL, NULL, NULL))
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
                                       (i == 0) ? share_commitment.data() : NULL, &(shares[i]),
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

void SignerApi::AggregateKeyShares()
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

signature SignerApi::AggregateSignatureShares()
{
    signature sig_agg;
    std::vector<secp256k1_frost_partial_sig> sigshares_data(m_threshold_size);
    std::vector<secp256k1_frost_partial_sig *> sigshares(m_threshold_size);

    std::transform(std::execution::par_unseq, m_sig_shares[m_opid].begin(), m_sig_shares[m_opid].end(), sigshares_data.begin(), [&](const auto& s)
    {
        //TODO: Remove init magics when secp256k1_frost_partial_sig_parse is fixed
        secp256k1_frost_partial_sig share {{0xeb, 0xfb, 0x1a, 0x32}};
        secp256k1_frost_partial_sig_parse(mWallet.GetSecp256k1Context(), &share, s.second.data());
        return share;
    });
    std::transform(std::execution::par_unseq, sigshares_data.begin(), sigshares_data.end(), sigshares.begin(), [](secp256k1_frost_partial_sig& s) { return &s; });

    if (!secp256k1_frost_partial_sig_agg(mWallet.GetSecp256k1Context(), sig_agg.data(), &(std::get<SIGSESSION>(m_sig_handlers[m_opid])), sigshares.data(), m_threshold_size)) {
        throw SignatureError();
    }
    else {
        return sig_agg;
    }
}

void SignerApi::InitSignature(operation_id opid, const uint256 &datahash, aggregate_sig_handler handler)
{
    if (opid != 0 && opid <= m_opid) {
        throw WrongOperationId(opid);
    }
    m_opid = opid;
    m_sig_handlers[opid] = sigstate(secp256k1_frost_session(), handler);

    secp256k1_frost_session* session = &(std::get<SIGSESSION>(m_sig_handlers[m_opid]));

    std::vector<secp256k1_frost_pubnonce> pubnonces_data(m_peers_data.size());
    std::vector<secp256k1_frost_pubnonce*> pubnonces(m_peers_data.size());
    std::vector<secp256k1_xonly_pubkey> pubkeys_data(m_peers_data.size());
    std::vector<secp256k1_xonly_pubkey*> pubkeys(m_peers_data.size());

    std::for_each(std::execution::par_unseq, m_peers_data.cbegin(), m_peers_data.cend(), [&](const RemoteSignerData& peer)
    {
        size_t peer_index = &peer - &(m_peers_data.front());

        auto I = peer.ephemeral_pubkeys.begin();
        std::advance(I, m_opid);
        std::copy(I->data(), I->data() + I->size(), pubnonces_data[peer_index].data);
        pubnonces[peer_index] = &pubnonces_data[peer_index];

        if (!secp256k1_xonly_pubkey_parse(mWallet.GetSecp256k1Context(), &pubkeys_data[peer_index], peer.pubkey.data())) {
            throw WrongKeyError();
        }
        pubkeys[peer_index] = &pubkeys_data[peer_index];
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

void SignerApi::DistributeSigShares()
{
    secp256k1_frost_session* session = &(std::get<SIGSESSION>(m_sig_handlers[m_opid]));

    secp256k1_frost_secnonce secnonce;
    auto secnonce_it = m_secnonces.begin();
    std::advance(secnonce_it, m_opid);
    std::copy(secnonce_it->begin(), secnonce_it->end(), secnonce.data);

    secp256k1_frost_share keyshare;
    std::copy(mKeyShare.GetLocalPrivKey().begin(), mKeyShare.GetLocalPrivKey().end(), keyshare.data);

    secp256k1_frost_partial_sig sigshare;
    if (!secp256k1_frost_partial_sign(mWallet.GetSecp256k1Context(), &sigshare, &secnonce, &keyshare, session, nullptr)) {
        throw SignatureError();
    }

    SignatureShare message(m_signer_index, m_opid);
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



} // l15