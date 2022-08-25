#pragma once

#include <list>
#include <memory>
#include <array>
#include <cmath>
#include <algorithm>
#include <execution>
#include <boost/container/flat_map.hpp>
#include <atomic>
#include <mutex>


#include "common.hpp"
#include "channel_keys.hpp"
#include "common_error.hpp"


#include "p2p_link.hpp"
#include "p2p_frost.hpp"
#include "secp256k1_frost.h"

namespace l15::core {

typedef size_t operation_id;
typedef size_t peer_index;

class KeyShareVerificationError : public KeyError {
public:
    ~KeyShareVerificationError() override = default;

    const char* what() const override
    { return "KeyShareVerificationError"; }

};

class KeyAggregationError : public KeyError {
public:
    ~KeyAggregationError() override = default;

    const char* what() const override
    { return "KeyAggregationError"; }

};
class WrongOperationId : public Error {
public:
    explicit WrongOperationId(operation_id id) : opid(id) {}
    ~WrongOperationId() override = default;

    const char* what() const override
    { return "WrongOperationId"; }

    operation_id opid;
};

class SignerApi;

typedef std::function<void(Error&&)> error_handler;
typedef std::function<void(SignerApi&)> aggregate_key_handler;
typedef std::function<void(SignerApi&, operation_id)> new_sigop_handler;
typedef std::function<void(SignerApi&, operation_id)> aggregate_sig_handler;


struct RemoteSignerData
{
    mutable std::shared_ptr<p2p::Link> link;
    secp256k1_xonly_pubkey pubkey;
    std::list<secp256k1_frost_pubnonce> ephemeral_pubkeys;

    std::vector<secp256k1_pubkey> keyshare_commitment; // k
    std::optional<secp256k1_frost_share> keyshare;

    RemoteSignerData() : link(nullptr), pubkey(), ephemeral_pubkeys(), keyshare_commitment(), keyshare(std::nullopt) {}

};


class SignerApi
{
    const secp256k1_context* m_ctx;
    ChannelKeys mKeypair;
    ChannelKeys mKeyShare;

    const size_t m_signer_index;
    size_t m_nonce_count;

    const size_t m_threshold_size;
    std::vector<RemoteSignerData> m_peers_data;
    std::atomic<size_t> m_keyshare_count;
    uint256 m_vss_hash;
    aggregate_key_handler m_key_handler;

    std::list<secp256k1_frost_secnonce> m_secnonces;

    std::array<void(SignerApi::*)(const p2p::Message& m), (size_t)p2p::FROST_MESSAGE::MESSAGE_ID_COUNT> mHandlers;

    std::mutex m_sig_share_mutex;

    typedef std::optional<frost_sigshare> sigop_peer_cache;
    typedef std::tuple<std::optional<secp256k1_frost_session>, boost::container::flat_map<peer_index, sigop_peer_cache>, size_t> sigop_cache;

    boost::container::flat_map<operation_id, sigop_cache> m_sigops_cache;

    const new_sigop_handler m_new_sig_handler;
    const aggregate_sig_handler m_aggregate_sig_handler;

    const error_handler m_err_handler;

    template<typename DATA>
    void Publish(const DATA& data) {
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
    void SendToPeers(std::function<void(DATA&, const RemoteSignerData&, size_t)> datagen) {
        std::for_each(std::execution::par_unseq, m_peers_data.cbegin(), m_peers_data.cend(), [&](const RemoteSignerData& peer)
        {
            size_t peer_index = &peer - &(m_peers_data.front());
            DATA data(m_signer_index);
            datagen(data, peer, peer_index);
            if (m_signer_index != peer_index) {
                peer.link->Send(data);
            }
            else {
                Accept(data);
            }
        });
    }

    std::optional<secp256k1_frost_session>& SigOpSession(operation_id opid)
    { return std::get<0>(m_sigops_cache[opid]); }

    boost::container::flat_map<peer_index, sigop_peer_cache>& SigOpCachedPeers(operation_id opid)
    { return std::get<1>(m_sigops_cache[opid]); }

    size_t& SigOpSigShareCount(operation_id opid)
    { return std::get<2>(m_sigops_cache[opid]); }

public:
    SignerApi(size_t index,
              ChannelKeys &&keypair,
              size_t cluster_size,
              size_t threshold_size,
              new_sigop_handler sigop,
              aggregate_sig_handler aggsig,
              error_handler e);

    size_t GetIndex() const noexcept
    { return m_signer_index; }

    const xonly_pubkey& GetLocalPubKey() const
    { return mKeypair.GetLocalPubKey(); }

    const xonly_pubkey& GetAggregatedPubKey() const
    { return mKeyShare.GetPubKey(); }

    size_t GetNonceCount() const noexcept
    { return m_nonce_count; }


    // Methods to access internal data to use by tests
    // -----------------------------------------------

    const seckey& GetSecKey() const
    { return mKeypair.GetLocalPrivKey(); }

    const std::list<secp256k1_frost_secnonce>& GetSecNonceList() const
    { return m_secnonces; }

    // -----------------------------------------------

    void AddPeer(size_t index, p2p::link_ptr link);
    const std::vector<RemoteSignerData>& Peers() const
    { return m_peers_data; }

    void Accept(const p2p::Message& m);

    void RegisterToPeers(aggregate_key_handler key_handler);
    void DistributeKeyShares();

    void CommitNonces(size_t count);


    void InitSignature(operation_id opid, bool participate = true);
    void PreprocessSignature(const uint256 &datahash, operation_id opid);
    void DistributeSigShares(operation_id opid);

    void Verify(const uint256& message, const signature& signature);

    void AggregateKey();
    signature AggregateSignature(operation_id opid);

    void ClearSignatureCache(operation_id opid);
private:


    void AcceptRemoteSigner(const p2p::Message& m);
    void AcceptNonceCommitments(const p2p::Message& m);
    void AcceptKeyShareCommitment(const p2p::Message& m);
    void AcceptKeyShare(const p2p::Message& m);
    void AcceptSignatureCommitment(const p2p::Message& m);
    void AcceptSignatureShare(const p2p::Message& m);


};

} // l15
