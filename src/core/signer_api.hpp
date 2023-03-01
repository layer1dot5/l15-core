#pragma once

#include <utility>
#include <list>
#include <memory>
#include <array>
#include <cmath>
#include <execution>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <map>
#include <functional>
#include <type_traits>

#include <tbb/concurrent_unordered_map.h>
#include <tbb/concurrent_vector.h>


#include "common.hpp"
#include "algorithm.hpp"
#include "channel_keys.hpp"
#include "common_error.hpp"


#include "p2p_link.hpp"
#include "p2p_frost.hpp"
#include "secp256k1_frost.h"

namespace l15::core {

typedef scalar operation_id;

class PeerNotFoundError : public Error {
public:
    explicit PeerNotFoundError(const xonly_pubkey& pk) : Error(hex(pk)) {}

    const char* what() const noexcept override
    { return "P                                                                                                                                                                                                                                                     eerNotFoundError"; }
};

class OutOfOrderMessageError : public Error {
public:
    explicit OutOfOrderMessageError(const p2p::FrostMessage& m) : Error(m.ToString()) {}

    const char* what() const noexcept override
    { return "OutOfOrderMessageError"; }
};

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

class SigNonceIdCollision : public Error {
public:
    explicit SigNonceIdCollision(const operation_id& id) : Error(hex(id)) {}
    ~SigNonceIdCollision() override = default;

    const char* what() const noexcept override
    { return "OperationIdCollision"; }
};


class OperationIdCollision : public Error {
public:
    explicit OperationIdCollision(operation_id id) : opid(id) {}
    ~OperationIdCollision() override = default;

    const char* what() const noexcept override
    { return "OperationIdCollision"; }

    operation_id opid;
};

class SigNonceNotAwailable : public Error {
public:
    explicit SigNonceNotAwailable(std::string&& details) noexcept : Error(move(details)) {}
    ~SigNonceNotAwailable() override = default;

    const char* what() const noexcept override
    { return "SigNonceNotAwailable"; }

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
MovingBinder<Callable, Args...> make_moving_callable(Callable f, Args&&... args)
{ return MovingBinder<Callable, Args...>(move(f), std::forward<Args>(args)...); }


typedef std::function<void()> general_handler;
typedef std::function<void(operation_id)> sigop_handler;

typedef std::function<void(p2p::frost_message_ptr)> frost_publish_handler;
typedef std::function<void(const xonly_pubkey& peer_pk, p2p::frost_message_ptr)> frost_peer_link_handler;

struct RemoteSignerData
{
    explicit RemoteSignerData(frost_peer_link_handler&& l)
        : link(move(l))
        , ephemeral_pubkeys()
        , ephemeral_pubkeys_mutex(std::make_unique<std::shared_mutex>())
        , keyshare_commitment()
        , keyshare() {}

    RemoteSignerData(RemoteSignerData&& r)
        : link(move(r.link))
        , ephemeral_pubkeys(move(r.ephemeral_pubkeys))
        , ephemeral_pubkeys_mutex(move(r.ephemeral_pubkeys_mutex))
        , keyshare_commitment(move(r.keyshare_commitment))
        , keyshare(move(r.keyshare)) {}

    mutable frost_peer_link_handler link;
    std::map<operation_id, std::tuple<secp256k1_frost_pubnonce, std::optional<operation_id>>> ephemeral_pubkeys;
    std::unique_ptr<std::shared_mutex> ephemeral_pubkeys_mutex;

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
    seckey m_keyshare_random_session;

    size_t m_nonce_count;

    frost_publish_handler m_publisher;

    const size_t m_threshold_size;
    peers_data_type m_peers_data;

    std::atomic<size_t> m_keycommit_count;
    std::atomic<size_t> m_keyshare_count;
    scalar m_vss_hash;

    std::unique_ptr<MovingBinderBase> m_key_commits_handler;
    std::unique_ptr<MovingBinderBase> m_key_handler;

    std::map<operation_id, std::tuple<secp256k1_frost_secnonce, std::optional<operation_id>>> m_secnonces;
    std::shared_mutex m_secnonces_mutex;

    std::array<void(SignerApi::*)(const p2p::FrostMessage& m), (size_t)p2p::FROST_MESSAGE::MESSAGE_ID_COUNT> mHandlers;

    std::shared_mutex m_sig_share_mutex;

    typedef std::optional<frost_sigshare> sigshare_cache;

    typedef tbb::concurrent_unordered_map<
                secp256k1_xonly_pubkey,
                sigshare_cache, l15::hash<secp256k1_xonly_pubkey>, l15::secp256k1_xonly_pubkey_equal
            > sigshare_peers_cache;

    typedef std::tuple<
                std::optional<secp256k1_frost_session>,
                sigshare_peers_cache,
                size_t, // sigshare count; TODO: provide atomicity
                std::unique_ptr<std::mutex>,
                std::unique_ptr<MovingBinderBase>, // all_signature_commitments_received_handler
                std::unique_ptr<MovingBinderBase>  // all_signature_shares_received_handler
            > sigop_cache;

    typedef std::map<operation_id, sigop_cache> sigops_cache;

    sigops_cache m_sigops_cache;

    general_handler m_err_handler;

    std::atomic_uint16_t m_operation_seqnum;

    void Publish(p2p::frost_message_ptr&& data)
    {
        Accept(*data); //Provide broadcasted data to self
        m_publisher(move(data));
    }

    template<typename DATA>
    void SendToPeers(std::function<void(DATA&, const xonly_pubkey&, const RemoteSignerData&)> datagen) {
        cex::for_each(std::execution::par, m_peers_data.begin(), m_peers_data.end(), [&](const auto& peer)
        {
            std::unique_ptr<DATA> data = std::make_unique<DATA>(m_operation_seqnum++, xonly_pubkey(mKeypair.GetLocalPubKey()));
            datagen(*data, peer.first, peer.second);
            if (mKeypair.GetLocalPubKey() != peer.first) {
                peer.second.link(peer.first, move(data));
            }
            else {
                Accept(*data);
            }
        });
    }

    static std::optional<secp256k1_frost_session>& SigOpSession(sigops_cache::value_type& op_val)
    { return std::get<0>(op_val.second); }

    static sigshare_peers_cache& SigOpSigShares(sigops_cache::value_type& op_val)
    { return std::get<1>(op_val.second); }

    static size_t& SigOpSigShareCount(sigops_cache::value_type& op_val)
    { return std::get<2>(op_val.second); }

    static std::mutex& SigOpSigShareMutex(sigops_cache::value_type& op_val)
    { return *std::get<3>(op_val.second); }

    static std::unique_ptr<MovingBinderBase>& SigOpCommitmentsReceived(sigops_cache::value_type& op_val)
    { return std::get<4>(op_val.second); }

    static std::unique_ptr<MovingBinderBase>& SigOpSigSharesReceived(sigops_cache::value_type& op_val)
    { return std::get<5>(op_val.second); }

    void CommitKeySharesImpl();
    void DistributeKeySharesImpl();
    void InitSignatureImpl(const operation_id& opid);

    operation_id SelectNonceId(const operation_id& opid);
    operation_id GetCorrespondingNonceId(const operation_id& opid, const xonly_pubkey& peer_pk) const;

public:
    SignerApi(ChannelKeys &&keypair,
              size_t cluster_size,
              size_t threshold_size);

    void SetErrorHandler(general_handler f)
    { m_err_handler = f; }

    const xonly_pubkey& GetLocalPubKey() const
    { return mKeypair.GetLocalPubKey(); }

    const xonly_pubkey& GetAggregatedPubKey() const
    { return mKeyShare.GetPubKey(); }

    size_t GetNonceCount() const noexcept
    { return m_nonce_count; }

    bool CheckReadyToSign(const operation_id& opid) const;

    void SetPublisher(frost_publish_handler h)
    { m_publisher = move(h); }

    // Methods to access internal data to use by tests
    // -----------------------------------------------

    const seckey& GetSecKey() const
    { return mKeypair.GetLocalPrivKey(); }

    // -----------------------------------------------

    template<typename LINK>
    void AddPeer(xonly_pubkey&& pk, LINK link)
    { m_peers_data.emplace(move(pk), RemoteSignerData{move(link)}); }

    const peers_data_type& Peers() const
    { return m_peers_data; }

    void Accept(const p2p::FrostMessage& m);

    template<typename Callable>
    void CommitKeyShares(const Callable& key_commits_received_handler)
    {
        m_key_commits_handler = std::make_unique<MovingBinder<Callable>>(key_commits_received_handler);
        CommitKeySharesImpl();
    }

    template<typename Callable, typename... Args>
    void CommitKeyShares(Callable&& key_commits_received_handler, Args&&... args)
    {
        m_key_commits_handler = std::make_unique<MovingBinder<Callable, Args...>>(std::forward<Callable>(key_commits_received_handler), std::forward<Args>(args)...);
        CommitKeySharesImpl();
    }

    template<typename Callable>
    void DistributeKeyShares(const Callable& key_shares_received_handler)
    {
        m_key_handler = std::make_unique<MovingBinder<Callable>>(key_shares_received_handler);
        DistributeKeySharesImpl();
    }

    template<typename Callable, typename... Args>
    void DistributeKeyShares(Callable&& key_shares_received_handler, Args&&... args)
    {
        m_key_handler = std::make_unique<MovingBinder<Callable, Args...>>(std::forward<Callable>(key_shares_received_handler), std::forward<Args>(args)...);
        DistributeKeySharesImpl();
    }

    void CommitNonces(size_t count);

    template<typename Callable1, typename Callable2>
    void InitSignature(const operation_id& opid,
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
                        std::make_unique<std::mutex>(),
                        std::make_unique<MovingBinder<Callable1>>(std::forward<Callable1>(all_sig_commitments_received_handler)),
                        std::make_unique<MovingBinder<Callable2>>(std::forward<Callable2>(all_sig_shares_received_handler)));

                m_sigops_cache.emplace(opid, move(peers_cache));
            }
            else {
                SigOpCommitmentsReceived(*opit) = std::make_unique<MovingBinder<Callable1>>(std::forward<Callable1>(all_sig_commitments_received_handler));
                SigOpSigSharesReceived(*opit) = std::make_unique<MovingBinder<Callable2>>(std::forward<Callable2>(all_sig_shares_received_handler));
            }
        }

        if (participate)
        {
            InitSignatureImpl(opid);
        }
    }

    void PreprocessSignature(const scalar &datahash, const operation_id& opid);


    template<typename Callable, typename... Args>
    void DistributeSigShares(const operation_id& opid, Callable&& sig_shares_received_handler, Args&&... args)
    {
        {
            std::unique_lock write_lock(m_sig_share_mutex);

            auto opit = m_sigops_cache.find(opid);
            if (opit != m_sigops_cache.end()) {
                SigOpSigSharesReceived(*opit) = std::make_unique<MovingBinder<Callable, Args...>>(std::forward<Callable>(sig_shares_received_handler), std::forward<Args>(args)...);
            }
            else {
                throw OperationIdCollision(opid);
            }
        }
        DistributeSigShares(opid);
    }

    template<typename Callable>
    void DistributeSigShares(const operation_id& opid, Callable&& sig_shares_received_handler)
    {
        {
            std::unique_lock write_lock(m_sig_share_mutex);

            auto opit = m_sigops_cache.find(opid);
            if (opit != m_sigops_cache.end()) {
                SigOpSigSharesReceived(*opit) = std::make_unique<MovingBinder<Callable>>(std::forward<Callable>(sig_shares_received_handler));
            }
            else {
                throw OperationIdCollision(opid);
            }
        }
        DistributeSigShares(opid);
    }

    void DistributeSigShares(const operation_id& opid);

    void Verify(const scalar& message, const signature& signature) const;

    void AggregateKey();
    signature AggregateSignature(const operation_id& opid);

    void ClearSignatureCache(const operation_id& opid);
private:

    void AcceptNonceCommitments(const p2p::FrostMessage& m);
    void AcceptKeyShareCommitment(const p2p::FrostMessage& m);
    void AcceptKeyShare(const p2p::FrostMessage& m);
    void AcceptSignatureCommitment(const p2p::FrostMessage& m);
    void AcceptSignatureShare(const p2p::FrostMessage& m);


};

} // l15
