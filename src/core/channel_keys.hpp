#pragma once

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_musig.h"

#include "random.h"

#include "common.hpp"

#include "wallet_api.hpp"

namespace l15 {

class KeyError {};
class WrongKeyError : public KeyError {};

class ChannelKeys
{
    const api::WalletApi& mWallet;
    seckey m_local_sk;
    xonly_pubkey m_local_pk;

    xonly_pubkey m_pubkey_agg;

    void CachePubkey();
public:
    explicit ChannelKeys(const api::WalletApi& wallet): mWallet(wallet), m_local_sk(GetStrongRandomKey()) { CachePubkey(); }
    explicit ChannelKeys(const api::WalletApi& wallet, seckey&& local_sk): mWallet(wallet), m_local_sk(local_sk) { CachePubkey(); }

    ChannelKeys(const ChannelKeys& other) : mWallet(other.mWallet), m_local_sk(other.m_local_sk), m_local_pk(other.m_local_pk), m_pubkey_agg(other.m_pubkey_agg)
    {
    }

    ChannelKeys(ChannelKeys &&old) noexcept : mWallet(old.mWallet), m_local_sk(std::move(old.m_local_sk)), m_local_pk(std::move(old.m_local_pk)), m_pubkey_agg(std::move(old.m_pubkey_agg))
    {
    }
//
//    ChannelKeys(CKey&& local_sk, XOnlyPubKey &&remote_pk)
//            : m_local_sk(std::move(local_sk)), m_remote_pk(std::move(remote_pk))
//    {}
//
//    ChannelKeys& operator=(const ChannelKeys& ) = delete;
    ChannelKeys& operator=(ChannelKeys&& old) noexcept
    {
        m_local_sk = std::move(old.m_local_sk);
        m_local_pk = std::move(old.m_local_pk);
        m_pubkey_agg = std::move(old.m_pubkey_agg);

        return *this;
    }

    void SetAggregatePubKey(const xonly_pubkey& pubkey)
    { m_pubkey_agg = pubkey; }
    //void AggregateMuSigPubKey(const std::vector<xonly_pubkey>& pubkeys);

    const seckey& GetLocalPrivKey() const
    { return m_local_sk; }

    const xonly_pubkey & GetLocalPubKey() const
    { return m_local_pk; }

    const xonly_pubkey& GetPubKey() const
    { return m_pubkey_agg; }

    std::pair<xonly_pubkey , uint8_t> AddTapTweak(std::optional<uint256>&& merkle_root) const;

    seckey GetStrongRandomKey();

    template<typename T>
    static bool IsZeroArray(const T& a)
    { bool res = false; std::for_each(a.begin(), a.end(), [&](const uint8_t& el){ res |= el; }); return !res;}
};

bool pubkey_less(const xonly_pubkey &, const xonly_pubkey &);

}
