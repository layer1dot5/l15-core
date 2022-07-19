#pragma once

#include <list>
#include <memory>
#include <array>
#include <cmath>
#include <algorithm>
#include <execution>
#include <unordered_map>
#include <atomic>
#include <mutex>


#include "common.hpp"
#include "channel_keys.hpp"

#include "p2p/link.hpp"
#include "p2p/frost.hpp"
#include "secp256k1_frost.h"

namespace l15 {

typedef size_t operation_id;

struct SignatureError {};
struct KeyAggregationError : public KeyError {};
struct WrongOperationId
{
    WrongOperationId(operation_id id) : opid(id) {}
    operation_id opid;
};

typedef std::function<void(operation_id, signature&&, std::optional<SignatureError> )> signature_handler;


struct RemoteSignerData
{
    mutable std::shared_ptr<p2p::Link> link;
    xonly_pubkey pubkey;
    std::list<frost_pubnonce> ephemeral_pubkeys;

    std::vector<compressed_pubkey> keyshare_commitment; // k
    seckey keyshare;
};


class SignerApi
{
    api::WalletApi& mWallet;

    ChannelKeys mKeypair;
    ChannelKeys mKeyShare;

    const size_t m_signer_index;
    size_t m_nonce_count;
    operation_id m_opid;

    const size_t m_threshold_size;
    std::vector<RemoteSignerData> m_peers_data;
    std::atomic<size_t> m_keyshare_count;
    uint256 m_vss_hash;

    std::list<frost_secnonce> m_secnonces;

    std::array<void(SignerApi::*)(const p2p::Message& m), (size_t)p2p::FROST_MESSAGE::MESSAGE_ID_COUNT> mHandlers;

    std::mutex m_sig_share_mutex;
    std::unordered_map<operation_id, std::unordered_map<size_t, frost_sigshare>> m_sig_shares;

    enum {SIGSESSION, SIGHANDLER};
    typedef std::tuple<secp256k1_frost_session, signature_handler> sigstate;
    std::unordered_map<operation_id, sigstate> m_sig_handlers;


    template<typename DATA>
    void SendToPeers(const DATA& data) {
        std::for_each(std::execution::par_unseq, m_peers_data.cbegin(), m_peers_data.cend(), [&](const RemoteSignerData& peer)
        {
            size_t peer_index = &peer - &(m_peers_data.front());
            if (m_signer_index != peer_index) {
                peer.link->Send(data);
            }
            else {
                Accept(data);
            }
        });
    }

    template<typename DATA>
    void SendToPeers(std::function<void(DATA&, size_t)> datagen) {
        std::for_each(std::execution::par_unseq, m_peers_data.cbegin(), m_peers_data.cend(), [&](const RemoteSignerData& peer)
        {
            size_t peer_index = &peer - &(m_peers_data.front());
            DATA data(m_signer_index);
            datagen(data, peer_index);
            if (m_signer_index != peer_index) {
                peer.link->Send(data);
            }
            else {
                Accept(data);
            }
        });
    }


public:
    SignerApi(api::WalletApi& wallet, size_t index, ChannelKeys &&keypair, size_t cluster_size, size_t threshold_size);

    size_t GetIndex() const noexcept
    { return m_signer_index; }

    const xonly_pubkey & GetLocalPubKey() const
    { return mKeypair.GetLocalPubKey(); }

    xonly_pubkey GetAggregatedPubKey() const
    { return mKeyShare.GetPubKey(); }

    size_t GetNonceCount() const noexcept
    { return m_nonce_count; }

    operation_id GetOpId() const noexcept
    { return m_opid; }


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
    void DistributeKeyShares();

    void InitSignature(operation_id opid, const uint256 &datahash, signature_handler handler);
    void DistributeSigShares();

    void Verify(const uint256& message, const signature& signature);

private:
    void AggregateKeyShares();
    void AggregateSignatureShares();


    void AcceptRemoteSigner(const p2p::Message& m);
    void AcceptNonceCommitments(const p2p::Message& m);
    void AcceptKeyShareCommitment(const p2p::Message& m);
    void AcceptKeyShare(const p2p::Message& m);
    void AcceptSignatureShare(const p2p::Message& m);


};

} // l15
