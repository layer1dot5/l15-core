#pragma once

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

#include "random.h"
#include "interpreter.h"

#include "common.hpp"
#include "common_error.hpp"

#include <optional>

#include "../../node/src/script/interpreter.h"

namespace l15::core {



class ChannelKeys
{
    const secp256k1_context* m_ctx;
    seckey m_local_sk;
    xonly_pubkey m_local_pk;

    xonly_pubkey m_pubkey_agg;

    void CachePubkey();
public:
    static secp256k1_context* GetStaticSecp256k1Context();

    explicit ChannelKeys(): m_ctx(GetStaticSecp256k1Context()), m_local_sk(GetStrongRandomKey()) { CachePubkey(); }
    explicit ChannelKeys(seckey local_sk): m_ctx(GetStaticSecp256k1Context()), m_local_sk(std::move(local_sk)) { CachePubkey(); }
    explicit ChannelKeys(const secp256k1_context* secp256k1_ctx): m_ctx(secp256k1_ctx), m_local_sk(GetStrongRandomKey()) { CachePubkey(); }
    explicit ChannelKeys(const secp256k1_context* secp256k1_ctx, seckey local_sk): m_ctx(secp256k1_ctx), m_local_sk(std::move(local_sk)) { CachePubkey(); }

    ChannelKeys(const ChannelKeys&) = default;
    ChannelKeys(ChannelKeys &&old) noexcept: m_ctx(old.m_ctx), m_local_sk(std::move(old.m_local_sk)), m_local_pk(std::move(old.m_local_pk)), m_pubkey_agg(std::move(old.m_pubkey_agg))
    {}

    ChannelKeys& operator=(ChannelKeys&& old) noexcept
    {
        m_local_sk = std::move(old.m_local_sk);
        m_local_pk = std::move(old.m_local_pk);
        m_pubkey_agg = std::move(old.m_pubkey_agg);

        return *this;
    }

    const secp256k1_context* Secp256k1Context() const noexcept
    { return m_ctx; }

    void SetAggregatePubKey(const xonly_pubkey&& pubkey)
    { m_pubkey_agg = pubkey; }

    const seckey& GetLocalPrivKey() const
    { return m_local_sk; }

    const xonly_pubkey& GetLocalPubKey() const
    { return m_local_pk; }

    const xonly_pubkey& GetPubKey() const
    { return m_pubkey_agg; }

    static std::pair<xonly_pubkey, uint8_t> AddTapTweak(const xonly_pubkey& pk, std::optional<uint256>&& merkle_root);

    std::pair<xonly_pubkey , uint8_t> AddTapTweak(std::optional<uint256>&& merkle_root) const;
    std::pair<ChannelKeys , uint8_t> NewKeyAddTapTweak(std::optional<uint256> merkle_root) const;

    seckey GetStrongRandomKey() const;

    signature SignSchnorr(const uint256& data) const;

    signature SignTaprootTx(const CMutableTransaction &tx, uint32_t nin, std::vector<CTxOut> &&spent_outputs,
                             const CScript &spend_script, int hashtype = SIGHASH_DEFAULT) const;
};

bool pubkey_less(const xonly_pubkey &, const xonly_pubkey &);

}
