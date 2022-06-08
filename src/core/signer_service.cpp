#include "signer_service.hpp"

#include <algorithm>
#include <execution>

namespace l15 {

using namespace p2p;

SignerService::SignerService(size_t index, ChannelKeys &&keypair, size_t cluster_size)
: m_index(index), mKeypair(keypair), m_peers_data(cluster_size)
{
    mHandlers[(size_t)FROST_MESSAGE::REMOTE_SIGNER] = &SignerService::AcceptRemoteSigner;
    mHandlers[(size_t)FROST_MESSAGE::NONCE_COMMITMENTS] = &SignerService::AcceptNonceCommitments;

    m_peers_data[index].pubkey = mKeypair.GetPubKey();
}

void SignerService::AddPeer(size_t index, link_ptr link)
{
    m_peers_data[index].link = link;
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

    if(remote_signer.index < m_peers_data.size() && m_peers_data[remote_signer.index].pubkey.empty())
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

    if(nonce_commitments.index < m_peers_data.size() && !(m_peers_data[nonce_commitments.index].pubkey.empty()))
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
    const RemoteSigner message{{(uint16_t)PROTOCOL::FROST, (uint16_t)FROST_MESSAGE::REMOTE_SIGNER}, (uint32_t)m_index, mKeypair.GetLocalPubKey()};
    std::for_each(std::execution::par_unseq, m_peers_data.cbegin(), m_peers_data.cend(), [&](const RemoteSignerData& peer)
        {
            size_t peer_index = &peer - &(m_peers_data.front());
            if (m_index != peer_index) {
                peer.link->Send(message);
            }
        });
}

void SignerService::CommitNonces(size_t count)
{

}

} // l15