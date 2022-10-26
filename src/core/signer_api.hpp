#pragma once

#include <utility>
#include <list>
#include <memory>
#include <array>
#include <cmath>
#include <algorithm>
#include <execution>
#include <boost/container/flat_map.hpp>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <functional>
#include <type_traits>


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

    const char* what() const noexcept override
    { return "KeyShareVerificationError"; }

};

class KeyAggregationError : public KeyError {
public:
    ~KeyAggregationError() override = default;

    const char* what() const noexcept override
    { return "KeyAggregationError"; }

};
class WrongOperationId : public Error {
public:
    explicit WrongOperationId(operation_id id) : opid(id) {}
    ~WrongOperationId() override = default;

    const char* what() const noexcept override
    { return "WrongOperationId"; }

    operation_id opid;
};

class SignerApi;

struct MovingBinderBase
{
    virtual ~MovingBinderBase() = default;
    virtual void operator()() = 0;
};

template <typename Callable, typename... Args>
struct MovingBinder : MovingBinderBase
{
    Callable m_f;
    std::tuple<Args...> m_args;

    explicit MovingBinder(Callable f, Args&&... args): m_f(move(f)), m_args(std::forward<Args>(args)...) {}

    MovingBinder(MovingBinder&& r) noexcept = default;

    void operator()() override {
        static_assert(std::is_invocable_v<Callable, Args&&...>);

        std::apply(m_f, move(m_args));
    }
};

template <typename Callable, typename... Args>
MovingBinder<Callable, Args...> make_callable_with_signer(Callable f, Args&&... args)
{ return MovingBinder<Callable, Args...>(move(f), std::forward<Args>(args)...); }


typedef std::function<void(Error&&)> error_handler;
typedef std::function<void()> general_handler;
typedef std::function<void(operation_id)> sigop_handler;


struct RemoteSignerData
{
    mutable p2p::frost_link_handler link;
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

    p2p::frost_link_handler m_publisher;

    const size_t m_threshold_size;
    peers_data_type m_peers_data;

    std::atomic<size_t> m_keyshare_count;
    uint256 m_vss_hash;

    std::unique_ptr<MovingBinderBase> m_key_handler;

    std::list<secp256k1_frost_secnonce> m_secnonces;

    std::array<void(SignerApi::*)(const p2p::FrostMessage& m), (size_t)p2p::FROST_MESSAGE::MESSAGE_ID_COUNT> mHandlers;

    std::shared_mutex m_sig_share_mutex;

    typedef std::optional<frost_sigshare> sigshare_cache;

    typedef std::unordered_map<
                secp256k1_xonly_pubkey,
                sigshare_cache, l15::hash<secp256k1_xonly_pubkey>, l15::secp256k1_xonly_pubkey_equal
            > sigshare_peers_cache;

    typedef std::tuple<
                std::optional<secp256k1_frost_session>,
                sigshare_peers_cache,
                size_t, // sigshare count; TODO: provide atomicity
                std::unique_ptr<MovingBinderBase>, // all_signature_commitments_received_handler
                std::unique_ptr<MovingBinderBase>  // all_signature_shares_received_handler
            > sigop_cache;

    typedef boost::container::flat_map<operation_id, sigop_cache> sigops_cache;

    sigops_cache m_sigops_cache;

    const error_handler m_err_handler;

    void Publish(const p2p::FrostMessage& data)
    {
        Accept(data); //Provide broadcasted data to self
        m_publisher(data);
    }

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

    std::unique_ptr<MovingBinderBase>& SigOpCommitmentsReceived(sigops_cache::iterator op_it)
    { return std::get<3>(op_it->second); }

    std::unique_ptr<MovingBinderBase>& SigOpSharesReceived(sigops_cache::iterator op_it)
    { return std::get<4>(op_it->second); }

    void DistributeKeySharesImpl();
    void InitSignatureImpl(operation_id opid);

public:
    SignerApi(ChannelKeys &&keypair,
              size_t cluster_size,
              size_t threshold_size,
              error_handler e);

    const xonly_pubkey& GetLocalPubKey() const
    { return mKeypair.GetLocalPubKey(); }

    const xonly_pubkey& GetAggregatedPubKey() const
    { return mKeyShare.GetPubKey(); }

    size_t GetNonceCount() const noexcept
    { return m_nonce_count; }


    void SetPublisher(p2p::frost_link_handler h)
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

    void Accept(const p2p::FrostMessage& m);

    template<typename Callable, typename... Args>
    void DistributeKeyShares(Callable key_shares_received_handler, Args&&... args)
    {
        m_key_handler = std::make_unique<MovingBinder<Callable, Args...>>(move(key_shares_received_handler), std::forward<Args>(args)...);
        DistributeKeySharesImpl();
    }

    void CommitNonces(size_t count);

    template<typename Callable1, typename Callable2>
    void InitSignature(operation_id opid,
                       Callable1&& all_sig_commitments_received_handler,
                       Callable2&& all_sig_shares_received_handler,
                       bool participate = true)
    {
        {
            [[maybe_unused]] std::unique_lock write_lock(m_sig_share_mutex);

            auto opit = m_sigops_cache.find(opid);
            if (opit == m_sigops_cache.end()) {
                sigop_cache peers_cache(
                        std::optional < secp256k1_frost_session > {},
                        sigshare_peers_cache(m_threshold_size),
                        (size_t)0,
                        std::make_unique<Callable1>(move(all_sig_commitments_received_handler)),
                        std::make_unique<Callable2>(move(all_sig_shares_received_handler)));

                m_sigops_cache.emplace(opid, move(peers_cache));
            }
            else {
                SigOpCommitmentsReceived(opit) = std::make_unique<Callable1>(move(all_sig_commitments_received_handler));
                SigOpSharesReceived(opit) = std::make_unique<Callable2>(move(all_sig_shares_received_handler));
            }
        }

        if (participate)
        {
            InitSignatureImpl(opid);
        }
    }

    void PreprocessSignature(const uint256 &datahash, operation_id opid);
    void DistributeSigShares(operation_id opid);

    void Verify(const uint256& message, const signature& signature) const;

    void AggregateKey();
    signature AggregateSignature(operation_id opid);

    void ClearSignatureCache(operation_id opid);
private:

    void AcceptNonceCommitments(const p2p::FrostMessage& m);
    void AcceptKeyShareCommitment(const p2p::FrostMessage& m);
    void AcceptKeyShare(const p2p::FrostMessage& m);
    void AcceptSignatureCommitment(const p2p::FrostMessage& m);
    void AcceptSignatureShare(const p2p::FrostMessage& m);


};

} // l15
