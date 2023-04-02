#include "swap_inscription.hpp"

#include "core_io.h"

#include "channel_keys.hpp"
#include "script_merkle_tree.hpp"




namespace l15::inscribeit {

namespace {

const uint32_t commit_timeout = 12;

CScript MakeOrdSwapScript(const xonly_pubkey& pk_A, const xonly_pubkey& pk_M)
{
    CScript script;
    script << pk_A << OP_CHECKSIG;
    script << pk_M << OP_CHECKSIGADD;
    script << 2 << OP_NUMEQUAL;
    return script;
}

CScript MakeFundsSwapScript(const bytevector& hash, const xonly_pubkey& pk_B, const xonly_pubkey& pk_M)
{
    CScript script;
    script << OP_HASH256 << hash << OP_EQUALVERIFY;
    script << pk_B << OP_CHECKSIG;
    script << pk_M << OP_CHECKSIGADD;
    script << 2 << OP_NUMEQUAL;
    return script;
}

CScript MakeRelTimeLockScript(uint32_t blocks_to_lock, const xonly_pubkey& pk)
{
    CScript script;
    script << GetCsvInBlocks(blocks_to_lock) << OP_CHECKSEQUENCEVERIFY << OP_DROP;
    script << pk << OP_CHECKSIG;
    return script;
}


void SignUtxo(const std::string& sk) {
    core::ChannelKeys utxo_key(unhex<seckey>(sk));

}

}

const std::string SwapInscriptionBuilder::name_ord_utxo_txid = "ord_utxo_txid";
const std::string SwapInscriptionBuilder::name_ord_utxo_nout = "ord_utxo_nout";
const std::string SwapInscriptionBuilder::name_ord_utxo_amount = "ord_utxo_amount";
const std::string SwapInscriptionBuilder::name_ord_utxo_pk_A = "ord_utxo_pk";
const std::string SwapInscriptionBuilder::name_ord_utxo_sig_A = "ord_utxo_sig";


const std::string SwapInscriptionBuilder::name_funds_utxo_txid = "funds_utxo_txid";
const std::string SwapInscriptionBuilder::name_funds_utxo_nout = "funds_utxo_nout";
const std::string SwapInscriptionBuilder::name_funds_utxo_amount = "funds_utxo_amount";
const std::string SwapInscriptionBuilder::name_funds_utxo_pk_B = "funds_utxo_pk";
const std::string SwapInscriptionBuilder::name_funds_utxo_sig_B = "funds_utxo_sig";

const std::string SwapInscriptionBuilder::name_swap_script_pk_M = "swap_script_pk_M";
const std::string SwapInscriptionBuilder::name_swap_hold_pk_M = "swap_hold_pk_M";
const std::string SwapInscriptionBuilder::name_swap_fee_pk_M = "swap_fee_pk_M";

xonly_pubkey SwapInscriptionBuilder::OrdCommitTapRoot() const
{
    ScriptMerkleTree tap_tree(TreeBalanceType::WEIGHTED,
                              { MakeOrdSwapScript(m_swap_script_pk_A.value(), m_swap_script_pk_M.value()),
                                MakeRelTimeLockScript(commit_timeout, m_swap_script_pk_A.value())});

    auto taproot = core::ChannelKeys::AddTapTweak(core::ChannelKeys::CreateUnspendablePubKey(m_ord_unspendable_key_factor.value()),
                                                  tap_tree.CalculateRoot());
    return get<0>(taproot);
}

xonly_pubkey SwapInscriptionBuilder::FundsCommitTapRoot() const
{
    ScriptMerkleTree tap_tree(TreeBalanceType::WEIGHTED,
                              { MakeFundsSwapScript(m_swap_hash.value(), m_swap_script_pk_B.value(), m_swap_script_pk_M.value()),
                                MakeRelTimeLockScript(commit_timeout, m_swap_script_pk_B.value())});

    auto taproot = core::ChannelKeys::AddTapTweak(core::ChannelKeys::CreateUnspendablePubKey(m_funds_unspendable_key_factor.value()),
                                                  tap_tree.CalculateRoot());
    return get<0>(taproot);
}


void SwapInscriptionBuilder::SignOrdUtxo(std::string ord_sk)
{
    core::ChannelKeys sk(unhex<seckey>(ord_sk));
    m_ord_utxo_pk = sk.GetLocalPubKey();

    CScript utxo_pubkeyscript;
    utxo_pubkeyscript << 1;
    utxo_pubkeyscript << *m_ord_utxo_pk;

    CScript commit_pubkeyscript;
    commit_pubkeyscript << 1;
    commit_pubkeyscript << OrdCommitTapRoot();

    CMutableTransaction commit_tx;
    commit_tx.vin = {CTxIn(COutPoint(uint256S(m_ord_txid.value()), m_ord_nout.value()))};
    commit_tx.vout = {CTxOut(m_ord_amount.value(), commit_pubkeyscript)};
    commit_tx.vin.front().scriptWitness.stack.emplace_back(64);

    size_t tx_size = GetSerializeSize(commit_tx, PROTOCOL_VERSION);
    commit_tx.vout.front().nValue = CalculateOutputAmount(*m_ord_amount, m_mining_fee_rate.value(), tx_size);

    m_ord_utxo_sig = sk.SignTaprootTx(commit_tx, 0, {CTxOut(*m_ord_amount, utxo_pubkeyscript)}, {});

    commit_tx.vin.front().scriptWitness.stack.front() = static_cast<bytevector&>(*m_ord_utxo_sig);

    mOrdCommitTx = commit_tx;
}

void SwapInscriptionBuilder::SignFundsUtxo(std::string funds_sk)
{
    core::ChannelKeys sk(unhex<seckey>(funds_sk));
    m_funds_utxo_pk = sk.GetLocalPubKey();

    CScript utxo_pubkeyscript;
    utxo_pubkeyscript << 1;
    utxo_pubkeyscript << *m_funds_utxo_pk;

    CScript commit_pubkeyscript;
    commit_pubkeyscript << 1;
    commit_pubkeyscript << FundsCommitTapRoot();

    CMutableTransaction commit_tx;
    commit_tx.vin = {CTxIn(COutPoint(uint256S(m_funds_txid.value()), m_funds_nout.value()))};
    commit_tx.vout = {CTxOut(m_funds_amount.value(), commit_pubkeyscript)};
    commit_tx.vin.front().scriptWitness.stack.emplace_back(64);

    size_t tx_size = GetSerializeSize(commit_tx, PROTOCOL_VERSION);
    commit_tx.vout.front().nValue = CalculateOutputAmount(*m_funds_amount, m_mining_fee_rate.value(), tx_size);

    m_funds_utxo_sig = sk.SignTaprootTx(commit_tx, 0, {CTxOut(*m_funds_amount, utxo_pubkeyscript)}, {});

    commit_tx.vin.front().scriptWitness.stack.front() = static_cast<bytevector&>(*m_funds_utxo_sig);

    mFundsCommitTx = commit_tx;
}


string SwapInscriptionBuilder::OrdCommitRawTransaction()
{
    if (!mOrdCommitTx) {
        throw std::logic_error("OrdCommit transaction data unavailable");
    }
    std::string res = EncodeHexTx(CTransaction(*mOrdCommitTx));
    return res;
}

string SwapInscriptionBuilder::FundsCommitRawTransaction()
{
    if (!mFundsCommitTx) {
        throw std::logic_error("FundsCommit transaction data unavailable");
    }
    std::string res = EncodeHexTx(CTransaction(*mFundsCommitTx));
    return res;
}

string SwapInscriptionBuilder::Serialize()
{
    return std::string();
}

void SwapInscriptionBuilder::Deserialize(string hex_data)
{

}



}
