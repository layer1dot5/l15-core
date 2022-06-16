#include "signer_service.hpp"

#include <utility>


namespace l15 {

using namespace p2p;

SignerService::SignerService(api::WalletApi& wallet, size_t index, ChannelKeys &&keypair, size_t cluster_size, size_t threshold_size)
: mWallet(wallet), mKeypair(keypair), m_signer_index(index), m_nonce_count(0), m_operation_index(0), m_peers_data(cluster_size)
{
    mHandlers[(size_t)FROST_MESSAGE::REMOTE_SIGNER] = &SignerService::AcceptRemoteSigner;
    mHandlers[(size_t)FROST_MESSAGE::NONCE_COMMITMENTS] = &SignerService::AcceptNonceCommitments;

    m_peers_data[index].pubkey = mKeypair.GetPubKey();
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
    const RemoteSigner &remote_signer = reinterpret_cast<const RemoteSigner &>(m);

    if(remote_signer.index < m_peers_data.size() && ChannelKeys::IsZeroArray(m_peers_data[remote_signer.index].pubkey))
    {
        m_peers_data[remote_signer.index].pubkey = remote_signer.pubkey;
    }
    else {
        throw WrongMessageData{m.protocol_id, m.id};
    }
}

void SignerService::AcceptNonceCommitments(const Message &m)
{
    const NonceCommitments& nonce_commitments = reinterpret_cast<const NonceCommitments&>(m);

    if(nonce_commitments.index < m_peers_data.size() && !ChannelKeys::IsZeroArray(m_peers_data[nonce_commitments.index].pubkey))
    {
        auto& ephemeral_pubkeys = m_peers_data[nonce_commitments.index].ephemeral_pubkeys;
        ephemeral_pubkeys.insert(ephemeral_pubkeys.end(), nonce_commitments.nonce_commitments.begin(),
                                                          nonce_commitments.nonce_commitments.end());
    }
    else {
        throw WrongMessageData{m.protocol_id, m.id};
    }
}

void SignerService::RegisterToPeers()
{
    const RemoteSigner message{{(uint16_t)PROTOCOL::FROST, (uint16_t)FROST_MESSAGE::REMOTE_SIGNER}, (uint32_t)m_signer_index, mKeypair.GetLocalPubKey()};
    SendToPeers(message);
}

void SignerService::CommitNonces(size_t count)
{

    m_secnonces.resize(m_nonce_count);
    m_peers_data[m_signer_index].ephemeral_pubkeys.resize(m_nonce_count);

    NonceCommitments message{{(uint16_t)PROTOCOL::FROST, (uint16_t)FROST_MESSAGE::NONCE_COMMITMENTS}, (uint32_t)m_signer_index};
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
        m_peers_data[m_signer_index].ephemeral_pubkeys.emplace_back(pubnonce_bytes);

        message.nonce_commitments.push_back(m_peers_data[m_signer_index].ephemeral_pubkeys.back());
    }

    SendToPeers(message);

    m_nonce_count += count;
}

} // l15