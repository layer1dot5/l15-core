#pragma once

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
//#include "secp256k1_musig.h"

#include "random.h"

#include "common.hpp"

#include "wallet_api.hpp"

namespace l15 {

class KeyError
{

};

class WrongKeyError : public KeyError
{

};

class ChannelKeys
{
    const api::WalletApi& mWallet;
    bytevector m_local_sk;
    bytevector m_local_pk;

    secp256k1_xonly_pubkey m_xonly_pubkey_agg;

    void MakeNewPrivKey();
public:
    explicit ChannelKeys(const api::WalletApi& wallet): mWallet(wallet), m_local_sk(), m_xonly_pubkey_agg{} { MakeNewPrivKey(); }
    explicit ChannelKeys(const api::WalletApi& wallet, bytevector&& local_sk): mWallet(wallet), m_local_sk(std::move(local_sk)), m_xonly_pubkey_agg{} {}

    void SetRemotePubKeys(const std::vector<bytevector>& pubkeys);
//    ChannelKeys(const ChannelKeys&) = delete;
//    ChannelKeys(ChannelKeys &&old) noexcept
//            : m_local_sk(std::move(old.m_local_sk)), m_remote_pk(std::move(old.m_remote_pk))
//    {}
//
//    ChannelKeys(CKey&& local_sk, XOnlyPubKey &&remote_pk)
//            : m_local_sk(std::move(local_sk)), m_remote_pk(std::move(remote_pk))
//    {}
//
//    ChannelKeys& operator=(const ChannelKeys& ) = delete;
//    ChannelKeys& operator=(ChannelKeys&& ) = delete;
//
    const bytevector& GetLocalPrivKey() const
    { return m_local_sk; }

    const bytevector& GetLocalPubKey() const
    { return m_local_pk; }

    bytevector GetPubKey() const;

    std::pair<bytevector, uint8_t> AddTapTweak(std::optional<uint256>&& merkle_root) const;
};

}
