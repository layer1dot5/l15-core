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
#include <unordered_map>
#include <functional>


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
typedef std::function<void(SignerApi&)> general_handler;
typedef std::function<void(SignerApi&, operation_id)> new_sigop_handler;
typedef std::function<void(SignerApi&, operation_id)> aggregate_sig_handler;


struct RemoteSignerData
{
    mutable p2p::link_handler link;
    std::list<secp256k1_frost_pubnonce> ephemeral_pubkeys;

    std::vector<secp256k1_pubkey> keyshare_commitment; // k
    std::optional<secp256k1_frost_share> keyshare;

};


class SignerApi
{
public:
    typedef std::unordered_map<xonly_pubkey, RemoteSignerData, l15::hash<xonly_pubkey>> peers_data_type;
private:
    const secp256k1_context* m_ctx;
    ChannelKeys mKeypair;
    ChannelKeys mKeyShare;

    size_t m_nonce_count;

    p2p::link_handler m_publisher;

    const size_t m_threshold_size;
    peers_data_type m_peers_data;

    std::atomic<size_t> m_keyshare_count;
    uint256 m_vss_hash;
    general_handler m_reg_handler;
    general_handler m_key_handler;

    std::list<secp256k1_frost_secnonce> m_secnonces;

    std::array<void(SignerApi::*)(const p2p::Message& m), (size_t)p2p::FROST_MESSAGE::MESSAGE_ID_COUNT> mHandlers;

    std::mutex m_sig_share_mutex;

    typedef std::optional<frost_sigshare> sigshare_cache;
    typedef std::unordered_map<secp256k1_xonly_pubkey, sigshare_cache, l15::hash<secp256k1_xonly_pubkey>, l15::secp256k1_xonly_pubkey_equal> sigshare_peers_cache;
    typedef std::tuple<std::optional<secp256k1_frost_session>, sigshare_peers_cache, size_t> sigop_cache;

    typedef boost::container::flat_map<operation_id, sigop_cache> sigops_cache;

    sigops_cache m_sigops_cache;

    const new_sigop_handler m_new_sig_handler;
    const aggregate_sig_handler m_aggregate_sig_handler;

    const error_handler m_err_handler;

    void Publish(const p2p::Message& data)
    { m_publisher(data); }

    template<typename DATA>
    void SendToPeers(std::function<void(DATA&, const xonly_pubkey&, const RemoteSignerData&)> datagen) {
        std::for_each(std::execution::par_unseq, m_peers_data.begin(), m_peers_data.end(), [&](const auto& peer)
        {
            DATA data(xonly_pubkey(mKeypair.GetLocalPubKey()));
            datagen(data, peer.first, peer.second);
            if (mKeypair.GetLocalPubKey() != peer.first) {
                peer.second.link(data);
            }
            else {
                Accept(data);
            }
        });
    }

    std::optional<secp256k1_frost_session>& SigOpSession(sigops_cache::iterator op_it)
    { return std::get<0>(op_it->second); }

    sigshare_peers_cache& SigOpCachedPeers(sigops_cache::iterator op_it)
    { return std::get<1>(op_it->second); }

    size_t& SigOpSigShareCount(sigops_cache::iterator op_it)
    { return std::get<2>(op_it->second); }

public:
    SignerApi(ChannelKeys &&keypair,
              size_t cluster_size,
              size_t threshold_size,
              new_sigop_handler sigop,
              aggregate_sig_handler aggsig,
              error_handler e);

    const xonly_pubkey& GetLocalPubKey() const
    { return mKeypair.GetLocalPubKey(); }

    const xonly_pubkey& GetAggregatedPubKey() const
    { return mKeyShare.GetPubKey(); }

    size_t GetNonceCount() const noexcept
    { return m_nonce_count; }


    void SetPublisher(p2p::link_handler h)
    { m_publisher = move(h); }

    // Methods to access internal data to use by tests
    // -----------------------------------------------

    const seckey& GetSecKey() const
    { return mKeypair.GetLocalPrivKey(); }

    const std::list<secp256k1_frost_secnonce>& GetSecNonceList() const
    { return m_secnonces; }

    // -----------------------------------------------

    template<typename LINK>
    void AddPeer(xonly_pubkey&& pk, LINK link)
    { m_peers_data.emplace(pk, RemoteSignerData{move(link)}); }

    const peers_data_type& Peers() const
    { return m_peers_data; }

    void Accept(const p2p::Message& m);

    void DistributeKeyShares(general_handler key_shares_received_handler);

    void CommitNonces(size_t count);


    void InitSignature(operation_id opid, bool participate = true);
    void PreprocessSignature(const uint256 &datahash, operation_id opid);
    void DistributeSigShares(operation_id opid);

    void Verify(const uint256& message, const signature& signature);

    void AggregateKey();
    signature AggregateSignature(operation_id opid);

    void ClearSignatureCache(operation_id opid);
private:

    void AcceptNonceCommitments(const p2p::Message& m);
    void AcceptKeyShareCommitment(const p2p::Message& m);
    void AcceptKeyShare(const p2p::Message& m);
    void AcceptSignatureCommitment(const p2p::Message& m);
    void AcceptSignatureShare(const p2p::Message& m);


};

} // l15
