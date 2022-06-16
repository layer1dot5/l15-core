#pragma once

#include <list>
#include <memory>
#include <array>
#include <cmath>
#include <algorithm>
#include <execution>


#include "common.hpp"
#include "channel_keys.hpp"

#include "p2p/link.hpp"
#include "p2p/frost.hpp"
#include "secp256k1_frost.h"

namespace l15 {

struct SignerError {

};


struct RemoteSignerData
{
    mutable std::shared_ptr<p2p::Link> link;
    xonly_pubkey pubkey;
    std::list<frost_pubnonce> ephemeral_pubkeys;
};


struct PubKeyShare
{
    std::vector<secp256k1_pubkey> pubkoef; // k
    std::vector<secp256k1_frost_share> shares; // n
};

class SignerService
{
    api::WalletApi& mWallet;

    ChannelKeys mKeypair;

    const size_t m_signer_index;
    size_t m_nonce_count;
    size_t m_operation_index;


    std::vector<RemoteSignerData> m_peers_data;
    std::list<frost_secnonce> m_secnonces;

    std::list<PubKeyShare> m_shares_for_peers;

    std::array<void(SignerService::*)(const p2p::Message& m), (size_t)p2p::FROST_MESSAGE::MESSAGE_ID_COUNT> mHandlers{};

    template<typename DATA>
    void SendToPeers(const DATA& data) {
        std::for_each(/*std::execution::par_unseq, */m_peers_data.cbegin(), m_peers_data.cend(), [&](const RemoteSignerData& peer)
        {
            size_t peer_index = &peer - &(m_peers_data.front());
            if (m_signer_index != peer_index) {
                peer.link->Send(data);
            }
        });
    }


public:
    SignerService(api::WalletApi& wallet, size_t index, ChannelKeys &&keypair, size_t cluster_size, size_t threshold_size);

    const xonly_pubkey & GetLocalPubKey() const
    { return mKeypair.GetLocalPubKey(); }

    size_t GetNonceCount() const
    { return m_nonce_count; }

    // Methods to access internal data to use by tests
    // -----------------------------------------------

    const seckey& GetSecKey() const
    { return mKeypair.GetLocalPrivKey(); }

    const std::list<frost_secnonce>& GetSecNonceList() const
    { return m_secnonces; }

    // -----------------------------------------------

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
