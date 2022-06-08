#pragma once

#include <list>
#include <memory>
#include <array>

#include "common.hpp"
#include "channel_keys.hpp"

#include "p2p/link.hpp"
#include "p2p/frost.hpp"

namespace l15 {


struct RemoteSignerData
{
    mutable std::shared_ptr<p2p::Link> link;
    bytevector pubkey;
    std::list<bytevector> ephemeral_pubkeys;
};

class SignerService
{
    const size_t m_index;
    ChannelKeys mKeypair;
    std::vector<RemoteSignerData> m_peers_data;

    std::array<void(SignerService::*)(const p2p::Message& m), (size_t)p2p::FROST_MESSAGE::MESSAGE_ID_COUNT> mHandlers;

public:
    SignerService(size_t index, ChannelKeys &&keypair, size_t cluster_size);

    const bytevector& GetLocalPubKey() const
    { return mKeypair.GetLocalPubKey(); }

    void AddPeer(size_t index, p2p::link_ptr link);
    const std::vector<RemoteSignerData>& Peers() const
    { return m_peers_data; }

    void Accept(const p2p::Message& m);

    void RegisterToPeers();
    void CommitNonces(size_t count);

private:
    void AcceptRemoteSigner(const p2p::Message& m);
    void AcceptNonceCommitments(const p2p::Message& m);






};

} // l15
