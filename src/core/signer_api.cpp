#include "signer_api.hpp"

#include <utility>
#include <sstream>
#include <type_traits>
#include <future>
#include <ranges>

#include "smartinserter.hpp"
#include "algorithm.hpp"

#include "util/strencodings.h"
#include "crypto/sha256.h"

#include "secp256k1_schnorrsig.h"


namespace l15::core {

using namespace p2p;

SignerApi::SignerApi(ChannelKeys &&keypair,
                     size_t cluster_size,
                     size_t threshold_size)

    : m_ctx(keypair.Secp256k1Context())
    , mKeypair(keypair)
    , mKeyShare(m_ctx)
    , m_keyshare_random_session()
    , m_nonce_count(0)
    , m_threshold_size(threshold_size)
    , m_peers_data(cluster_size)
    , m_keycommit_count(0)
    , m_keyshare_count(0)
    , m_vss_hash()
    , m_key_handler()
    , m_secnonces()
    , m_secnonces_mutex()
    , mHandlers()
    , m_err_handler([](){})
    , m_operation_seqnum(1)
{
    mHandlers[(size_t)FROST_MESSAGE::NONCE_COMMITMENTS] = &SignerApi::AcceptNonceCommitments;
    mHandlers[(size_t)FROST_MESSAGE::KEY_COMMITMENT] = &SignerApi::AcceptKeyShareCommitment;
    mHandlers[(size_t)FROST_MESSAGE::KEY_SHARE] = &SignerApi::AcceptKeyShare;
    mHandlers[(size_t)FROST_MESSAGE::SIGNATURE_COMMITMENT] = &SignerApi::AcceptSignatureCommitment;
    mHandlers[(size_t)FROST_MESSAGE::SIGNATURE_SHARE] = &SignerApi::AcceptSignatureShare;

    AddPeer(xonly_pubkey(mKeypair.GetLocalPubKey()), [this](const xonly_pubkey& pk, p2p::frost_message_ptr&& m){ Accept(*m); });
}

bool SignerApi::CheckReadyToSign(const operation_id& opid) const
{
    bool res = mKeyShare.GetPubKey() != mKeyShare.GetLocalPubKey();

    if (res) {
        try {
            for (const auto &peer_data: m_peers_data) {
                GetCorrespondingNonceId(opid, peer_data.first);
            }
            res = true;
        }
        catch (...) {
            res = false;
        }
    }
    return res;
}

void SignerApi::Accept(const FrostMessage& m)
{
    try {
        if (m.protocol_id != PROTOCOL::FROST) {
            throw WrongProtocol(static_cast<std::underlying_type<PROTOCOL>::type>(m.protocol_id));
        }

        if (static_cast<uint16_t>(m.id) < static_cast<uint16_t>(FROST_MESSAGE::MESSAGE_ID_COUNT)) {
            //std::clog << (stringstream() << std::hex << std::this_thread::get_id() << " [" << hex(mKeypair.GetPubKey()).substr(0, 8) << "] " << m.ToString()).str() << std::endl;

            (this->*mHandlers[static_cast<uint16_t>(m.id)])(m);
        }
        else {
            throw WrongMessage(m);
        }
    }
    catch(...) {
        m_err_handler();
    }
}


void SignerApi::AcceptNonceCommitments(const FrostMessage &m)
{
    const auto& message = reinterpret_cast<const NonceCommitments&>(m);

    if (m_peers_data.contains(message.pubkey)) {
        auto& peer_data = m_peers_data.at(message.pubkey);
        auto& ephemeral_pubkeys = peer_data.ephemeral_pubkeys;

        std::unique_lock lock(*peer_data.ephemeral_pubkeys_mutex);

        for (const auto& pubnonce: message.nonce_commitments)
        {
            scalar nonceid;
            CSHA256().Write(pubnonce.data, sizeof(pubnonce.data)).Finalize(nonceid.data());
            std::get<0>(ephemeral_pubkeys[nonceid]) = pubnonce;
        }
    }
    else {
        throw PeerNotFoundError(message.pubkey);
    }
}

void SignerApi::AcceptKeyShareCommitment(const FrostMessage &m)
{
    const auto& message = reinterpret_cast<const KeyShareCommitment&>(m);

    auto peer_it = m_peers_data.find(message.pubkey);
    if (peer_it != m_peers_data.end()/*
        && peer_it->second.keyshare_commitment.empty()*/)
    {
        bool was_empty = peer_it->second.keyshare_commitment.empty();
        peer_it->second.keyshare_commitment = message.share_commitment;
        if (was_empty && ++m_keycommit_count >= m_peers_data.size()) {
            (*m_key_commits_handler)();
        }
    }
    else {
        throw PeerNotFoundError(message.pubkey);
    }
}

void SignerApi::AcceptKeyShare(const FrostMessage &m)
{
    const auto& message = reinterpret_cast<const KeyShare&>(m);

    auto peer_it = m_peers_data.find(message.pubkey);
    if (peer_it == m_peers_data.end()) {
        throw PeerNotFoundError(message.pubkey);
    }
    else if (!peer_it->second.keyshare_commitment.empty()) {

        if (peer_it->second.keyshare.has_value()) {
            if (memcmp(peer_it->second.keyshare->data, message.share.data, sizeof(secp256k1_frost_share)) != 0) {
                throw WrongMessageData(message);
            }
        }
        else {
            peer_it->second.keyshare = message.share;

            if (++m_keyshare_count >= m_peers_data.size()) {
                //std::clog << "KeyShare api received" << std::endl;
                (*m_key_handler)();
            }
        }
    }
    else {
        throw OutOfOrderMessageError(message);
    }
}

void SignerApi::AcceptSignatureCommitment(const p2p::FrostMessage& m)
{
    const auto& message = reinterpret_cast<const SignatureCommitment&>(m);

    auto peer_it = m_peers_data.find(message.pubkey);
    if (peer_it == m_peers_data.end()) {
        throw PeerNotFoundError(message.pubkey);
    }
    else if (mKeyShare.GetPubKey() != mKeyShare.GetLocalPubKey()) { // Means aggregated pub key is assigned

        std::shared_lock lock(*peer_it->second.ephemeral_pubkeys_mutex);
        auto& pubnonce_data = peer_it->second.ephemeral_pubkeys[message.nonce_id];

        if (!get<1>(pubnonce_data).has_value()) {
            get<1>(pubnonce_data) = std::make_optional(message.operation_id);
        }
        else if (*get<1>(pubnonce_data) != message.operation_id) {
            throw OperationIdCollision(message.operation_id);
        }
        lock.unlock();

        if (std::get<1>(pubnonce_data).has_value() && *std::get<1>(pubnonce_data) != message.operation_id) {
            throw OperationIdCollision(message.operation_id);
        }
        std::get<1>(pubnonce_data).emplace(message.operation_id);

        secp256k1_xonly_pubkey peer_pk = message.pubkey.get(m_ctx);

        [[maybe_unused]] std::unique_lock read_lock(m_sig_share_mutex);

        auto opit = m_sigops_cache.find(message.operation_id);
        if (opit == m_sigops_cache.end()) {
            sigop_cache peers_cache {
                std::optional<secp256k1_frost_session>(),
                sigshare_peers_cache(m_threshold_size),
                (size_t)0,
                std::make_unique<std::mutex>(),
                std::unique_ptr<MovingBinderBase>(),
                std::unique_ptr<MovingBinderBase>()};
            get<1>(peers_cache).emplace(move(peer_pk), sigshare_cache());

            m_sigops_cache.emplace(message.operation_id, move(peers_cache));

            // Anyway no need to check and call handler!!
        }
        else {
            auto& op = *opit;
            read_lock.unlock();
            //---------------//

            std::unique_lock shares_lock(SigOpSigShareMutex(op));
            SigOpSigShares(op).emplace(move(peer_pk), sigshare_cache());
            shares_lock.unlock();

            if (SigOpSigShares(op).size() >= m_threshold_size && SigOpCommitmentsReceived(op)) {
                (*SigOpCommitmentsReceived(op))();
            }
        }
    }
    else {
        throw OutOfOrderMessageError(message);
    }
}

void SignerApi::AcceptSignatureShare(const FrostMessage &m)
{
    const auto& message = reinterpret_cast<const SignatureShare&>(m);

    auto peer_it = m_peers_data.find(message.pubkey);
    if (peer_it == m_peers_data.end()) {
        throw PeerNotFoundError(message.pubkey);
    }
    else if (mKeyShare.GetPubKey() != mKeyShare.GetLocalPubKey()) // Means aggregated pub key is assigned
    {
        sigops_cache::value_type* op;
        {
            [[maybe_unused]] std::shared_lock read_lock(m_sig_share_mutex);

            sigops_cache::iterator op_it = m_sigops_cache.find(message.operation_id);
            if (op_it == m_sigops_cache.end()) {
                throw SignatureError((std::stringstream() << "Signature operation is not found: " << message.ToString()).str());
            }
            else {
                op = &*op_it;
            }
        }

        std::unique_lock shares_lock(SigOpSigShareMutex(*op));
        auto peer_cache_it = SigOpSigShares(*op).find(message.pubkey.get(m_ctx));

        if (peer_cache_it != SigOpSigShares(*op).end()) {
            if (!peer_cache_it->second.has_value()) {
                peer_cache_it->second = message.share;
                ++SigOpSigShareCount(*op);
            }
            else {
                if (peer_cache_it->second != message.share) {
                    shares_lock.unlock();
                    //-----------------//

                    std::ostringstream errbuf;
                    errbuf << "Peer is already provided different sig share: " << hex(message.operation_id) << '/' << hex(message.pubkey);
                    throw SignatureError(errbuf.str());
                }
            }
        }
        else {
            shares_lock.unlock();
            //-----------------//

            std::ostringstream errbuf;
            errbuf << '[' << hex(mKeypair.GetPubKey()).substr(0, 8) << "] "<< "Peer is not registered to participate in signature: " << hex(message.operation_id) << '/' << HexStr(message.pubkey);
            throw SignatureError(errbuf.str());
        }

        if (SigOpSigShareCount(*op) == m_threshold_size && SigOpSigSharesReceived(*op)) {
            shares_lock.unlock();
            //-----------------//

            (*SigOpSigSharesReceived(*op))();
        }
    }
    else {
        throw OutOfOrderMessageError(message);
    }
}


void SignerApi::CommitNonces(size_t count)
{
    std::unique_ptr<NonceCommitments> message = std::make_unique<NonceCommitments>(m_operation_seqnum++, xonly_pubkey(mKeypair.GetPubKey()));
    message->nonce_commitments.reserve(count);

    std::vector<std::pair<operation_id, std::tuple<secp256k1_frost_secnonce, std::optional<operation_id>>>> secnonces;
    secnonces.reserve(count);

    for (size_t i = 0; i < count; ++i) {
        seckey session_key = mKeypair.GetStrongRandomKey();
        secp256k1_frost_secnonce secnonce;
        secp256k1_frost_pubnonce pubnonce;

        if (!secp256k1_frost_nonce_gen(m_ctx, &secnonce, &pubnonce, session_key.data(), nullptr, nullptr, nullptr, nullptr)) {
            throw SignatureError("Pubnonce generation error");
        }

        scalar nonceid;
        CSHA256().Write(pubnonce.data, sizeof(pubnonce.data)).Finalize(nonceid.data());

        secnonces.emplace_back(move(nonceid), std::make_tuple(secnonce, std::optional<operation_id>()));
        message->nonce_commitments.emplace_back(pubnonce);
    }

    Publish(move(message));

    std::unique_lock lock(m_secnonces_mutex);
    m_secnonces.insert(std::make_move_iterator(secnonces.begin()), std::make_move_iterator(secnonces.end()));
    m_nonce_count += count;
}

void SignerApi::CommitKeySharesImpl()
{
    GetStrongRandBytes(m_keyshare_random_session);

    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(m_ctx, &keypair, mKeypair.GetLocalPrivKey().data())) {
        throw WrongKeyError();
    }

    //TODO: Optimization is needed by parallelisation (but only when secp256k1_frost is optimized at commitment generation)

    secp256k1_frost_share tmp_share;
    std::unique_ptr<KeyShareCommitment> message = std::make_unique<KeyShareCommitment>(m_operation_seqnum++, xonly_pubkey(mKeypair.GetPubKey()));
    message->share_commitment.resize(m_threshold_size);

    secp256k1_xonly_pubkey thispk = mKeypair.GetPubKey().get(m_ctx);

    if (!secp256k1_frost_share_gen(m_ctx,
                                   message->share_commitment.data(), &(tmp_share),
                                   m_keyshare_random_session.data(), &keypair, &thispk, m_threshold_size)) {
        throw SignatureError("FROST share generation error");
    }

    Publish(move(message));
}

void SignerApi::DistributeKeySharesImpl()
{
    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(m_ctx, &keypair, mKeypair.GetLocalPrivKey().data())) {
        throw WrongKeyError();
    }

    SendToPeers<KeyShare>([&](KeyShare& m, const xonly_pubkey& remote_pk, const RemoteSignerData& s){
        secp256k1_xonly_pubkey pk = remote_pk.get(m_ctx);
        if (!secp256k1_frost_share_gen(m_ctx,
                                       nullptr, &(m.share),
                                       m_keyshare_random_session.data(), &keypair, &pk, m_threshold_size)) {
            throw SignatureError("secp256k1_frost_share_gen");
        }
    });
}

void SignerApi::AggregateKey()
{
    std::vector<const secp256k1_frost_share*> shares; shares.reserve(m_peers_data.size());
    std::vector<const secp256k1_pubkey*> commitments; commitments.reserve(m_peers_data.size());

    std::for_each(m_peers_data.cbegin(), m_peers_data.cend(), [&](const auto& s)
    {
        if (!s.second.keyshare.has_value()) {
            throw KeyAggregationError();
        }
        shares.emplace_back(&s.second.keyshare.value());
        commitments.emplace_back(s.second.keyshare_commitment.data());

    });

    secp256k1_xonly_pubkey signer_pk = GetLocalPubKey().get(m_ctx);

    cex::for_each(std::execution::par_unseq, m_peers_data.begin(), m_peers_data.end(), [&](auto & s)
    {
        secp256k1_pubkey* commitment = s.second.keyshare_commitment.data();
        if (!secp256k1_frost_share_verify(m_ctx, m_threshold_size, &signer_pk, &s.second.keyshare.value(), &(commitment))) {
            throw KeyShareVerificationError();
        }
    });

    secp256k1_frost_share agg_share;
    secp256k1_xonly_pubkey agg_pk;

    if (!secp256k1_frost_share_agg(m_ctx,
                                   &agg_share, &agg_pk,
                                   m_vss_hash.data(),
                                   shares.data(), commitments.data(),
                                   m_peers_data.size(), m_threshold_size,
                                   &signer_pk)) {

        throw KeyAggregationError();
    }

    std::for_each(std::execution::par, m_peers_data.begin(), m_peers_data.end(), [](auto & s)
    {
        s.second.keyshare_commitment.clear();
        s.second.keyshare.reset();
    });

    seckey share;
    std::copy(agg_share.data, agg_share.data + sizeof(agg_share.data), share.begin());

    xonly_pubkey agg_pubkey;
    agg_pubkey.set(m_ctx, agg_pk);

    mKeyShare = ChannelKeys(m_ctx, std::move(share));
    mKeyShare.SetAggregatePubKey(std::move(agg_pubkey));
}

signature SignerApi::AggregateSignature(const operation_id& opid)
{
    signature sig_agg;
    std::vector<secp256k1_frost_partial_sig> sigshares_data(m_threshold_size);
    std::vector<secp256k1_frost_partial_sig *> sigshares(m_threshold_size);

    sigops_cache::value_type* op;
    {
        [[maybe_unused]] std::shared_lock read_lock(m_sig_share_mutex);

        auto op_it = m_sigops_cache.find(opid);
        if (op_it == m_sigops_cache.end()) {
            throw SignatureError((std::stringstream() << "Signature operation is not found: " << hex(opid).substr(0, 8) << "...").str());
        }
        op = &*op_it;
    }

    cex::transform(std::execution::par_unseq, SigOpSigShares(*op).begin(), SigOpSigShares(*op).end(), sigshares_data.begin(), [&](const auto& s)
    {
        secp256k1_frost_partial_sig share;
        if (!secp256k1_frost_partial_sig_parse(m_ctx, &share, s.second->data())) {
            throw SignatureError("Signature aggregation error");
        }
        return share;
    });

    std::transform(std::execution::par_unseq, sigshares_data.begin(), sigshares_data.end(), sigshares.begin(), [](secp256k1_frost_partial_sig& s) { return &s; });

    if (!secp256k1_frost_partial_sig_agg(m_ctx, sig_agg.data(), &(SigOpSession(*op).value()), sigshares.data(), m_threshold_size)) {
        throw SignatureError("Signature aggregation error");
    }
    else {
        return sig_agg;
    }
}

void SignerApi::InitSignatureImpl(const operation_id& opid)
{
    Publish(std::make_unique<SignatureCommitment>(m_operation_seqnum++, xonly_pubkey(mKeypair.GetLocalPubKey()), opid, SelectNonceId(opid)));
}

void SignerApi::PreprocessSignature(const scalar &datahash, const operation_id& opid)
{
    sigops_cache::value_type* op;
    {
        [[maybe_unused]] std::shared_lock read_lock(m_sig_share_mutex);

        auto op_it = m_sigops_cache.find(opid);
        if (op_it == m_sigops_cache.end()) {
            throw SignatureError((stringstream() << "Signature operation is not found: " << hex(opid).substr(0,8) << "...").str());
        }
        op = &*op_it;
    }

    const auto& sigshares = SigOpSigShares(*op);

    if (sigshares.size() < m_threshold_size) {
        throw SignatureError((stringstream() << "Not enough participants: " << sigshares.size()).str());
    }

    SigOpSession(*op).emplace(secp256k1_frost_session());

    std::vector<const secp256k1_frost_pubnonce*> pubnonces; pubnonces.reserve(m_threshold_size);
    std::vector<const secp256k1_xonly_pubkey*> pubkeys; pubkeys.reserve(m_threshold_size);

    std::mutex m;
    cex::for_each(std::execution::par, sigshares.begin(), sigshares.end(), [&](const auto& ss)
    {
        xonly_pubkey peer_pk(m_ctx, ss.first);
        const RemoteSignerData& peer = m_peers_data.at(peer_pk);

        std::shared_lock peer_lock(*peer.ephemeral_pubkeys_mutex);
        auto pubnonce_it = peer.ephemeral_pubkeys.find(GetCorrespondingNonceId(opid, peer_pk));

        if (pubnonce_it == peer.ephemeral_pubkeys.end()) {
            throw SignatureError((stringstream() << "No pubnonce from: " << hex(peer_pk)).str());
        }
        peer_lock.unlock(); // Unlock as search has been completed.

        {
            [[maybe_unused]] std::lock_guard lock(m);

            pubnonces.emplace_back(&(get<0>(pubnonce_it->second)));
            pubkeys.emplace_back(&(ss.first));
        }
    });

    secp256k1_xonly_pubkey pubkey_agg = mKeyShare.GetPubKey().get(m_ctx);

    secp256k1_xonly_pubkey pubkey = mKeypair.GetLocalPubKey().get(m_ctx);

    if (!secp256k1_frost_nonce_process(m_ctx, &(*SigOpSession(*op)), pubnonces.data(), m_threshold_size,
                                       datahash.data(), &pubkey_agg, &pubkey, pubkeys.data(), nullptr, nullptr)) {
        throw SignatureError("FROST Nonce processing error");
    }

}

void SignerApi::DistributeSigShares(const operation_id& opid)
{
    secp256k1_frost_session* session;
    {
        [[maybe_unused]] std::shared_lock read_lock(m_sig_share_mutex);

        auto op_it = m_sigops_cache.find(opid);
        if (op_it == m_sigops_cache.end() || !SigOpSession(*op_it).has_value()) {
            throw SignatureError((std::stringstream() << "Signature operation is not found: " << hex(opid).substr(0, 8) << "...").str());
        }

        session = &(SigOpSession(*op_it).value());
    }

    std::shared_lock secnonces_lock(m_secnonces_mutex);
    auto& secnonce = get<0>(m_secnonces.at(GetCorrespondingNonceId(opid, mKeypair.GetLocalPubKey())));
    secnonces_lock.unlock();

    secp256k1_frost_share keyshare;
    std::copy(mKeyShare.GetLocalPrivKey().begin(), mKeyShare.GetLocalPrivKey().end(), keyshare.data);

    secp256k1_frost_partial_sig sigshare;
    if (!secp256k1_frost_partial_sign(m_ctx, &sigshare, &secnonce, &keyshare, session, nullptr)) {
        throw SignatureError("Signing error");
    }

    std::unique_ptr<SignatureShare> message = std::make_unique<SignatureShare>(m_operation_seqnum++, xonly_pubkey(mKeypair.GetPubKey()), opid);
    secp256k1_frost_partial_sig_serialize(m_ctx, message->share.data(), &sigshare);

    Publish(move(message));
}

void SignerApi::Verify(const scalar &message, const signature &signature) const
{
    secp256k1_xonly_pubkey pubkey = mKeyShare.GetPubKey().get(m_ctx);

    if (!secp256k1_schnorrsig_verify(m_ctx, signature.data(), message.data(), 32, &pubkey)) {
        throw SignatureError("Signature does not match");
    }

}

void SignerApi::ClearSignatureCache(const operation_id& opid)
{
    [[maybe_unused]] std::unique_lock write_lock(m_sig_share_mutex);
    m_sigops_cache.erase(opid);
}

operation_id SignerApi::SelectNonceId(const operation_id &opid)
{
    std::unique_lock lock(m_secnonces_mutex);
    for (auto& secnonce: m_secnonces) {
        if (!std::get<1>(secnonce.second).has_value()) {
            std::get<1>(secnonce.second) = std::make_optional<operation_id>(opid);
            return secnonce.first;
        }
    }
    throw SigNonceNotAwailable();
}


operation_id SignerApi::GetCorrespondingNonceId(const operation_id &opid, const xonly_pubkey& peer_pk) const
{
    auto peer_it = m_peers_data.find(peer_pk);
    if (peer_it != m_peers_data.end()) {

        auto nonce_it = std::find_if(peer_it->second.ephemeral_pubkeys.begin(),
                                     peer_it->second.ephemeral_pubkeys.end(),
                                     [&opid](const auto& e){ return get<1>(e.second).has_value() && (*get<1>(e.second) == opid); });

        if (nonce_it != peer_it->second.ephemeral_pubkeys.end()) {
            return nonce_it->first;
        }
        else {
            throw SigNonceNotAwailable();
        }
    }
    else {
        throw UnknownPeer(hex(peer_pk));
    }
}

} // l15