#include "swap_inscription.hpp"

#include "core_io.h"

#include "channel_keys.hpp"


namespace l15::inscribeit {

namespace {

const uint32_t COMMIT_TIMEOUT = 12;

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

std::tuple<xonly_pubkey, uint8_t, ScriptMerkleTree> SwapInscriptionBuilder::OrdCommitTapRoot() const
{
    ScriptMerkleTree tap_tree(TreeBalanceType::WEIGHTED,
                              { MakeOrdSwapScript(m_swap_script_pk_A.value(), m_swap_script_pk_M.value()),
                                MakeRelTimeLockScript(COMMIT_TIMEOUT, m_swap_script_pk_A.value())});

    return std::tuple_cat(core::ChannelKeys::AddTapTweak(core::ChannelKeys::CreateUnspendablePubKey(m_ord_unspendable_key_factor.value()),
                                                  tap_tree.CalculateRoot()), std::make_tuple(tap_tree));
}

std::tuple<xonly_pubkey, uint8_t, ScriptMerkleTree> SwapInscriptionBuilder::FundsCommitTapRoot() const
{
    ScriptMerkleTree tap_tree(TreeBalanceType::WEIGHTED,
                              { MakeFundsSwapScript(m_swap_hash.value(), m_swap_script_pk_B.value(), m_swap_script_pk_M.value()),
                                MakeRelTimeLockScript(COMMIT_TIMEOUT, m_swap_script_pk_B.value())});

    return std::tuple_cat(core::ChannelKeys::AddTapTweak(core::ChannelKeys::CreateUnspendablePubKey(m_funds_unspendable_key_factor.value()),
                                                  tap_tree.CalculateRoot()), std::make_tuple(tap_tree));
}


void SwapInscriptionBuilder::SignOrdCommitment(std::string sk)
{
    core::ChannelKeys keypair(unhex<seckey>(sk));
    m_ord_utxo_pk = keypair.GetLocalPubKey();

    CScript utxo_pubkeyscript;
    utxo_pubkeyscript << 1;
    utxo_pubkeyscript << *m_ord_utxo_pk;

    CScript commit_pubkeyscript;
    commit_pubkeyscript << 1;
    commit_pubkeyscript << get<0>(OrdCommitTapRoot());

    CMutableTransaction commit_tx;
    commit_tx.vin = {CTxIn(COutPoint(uint256S(m_ord_txid.value()), m_ord_nout.value()))};
    commit_tx.vout = {CTxOut(m_ord_amount.value(), commit_pubkeyscript)};
    commit_tx.vin.front().scriptWitness.stack.emplace_back(64);

    size_t tx_size = GetSerializeSize(commit_tx, PROTOCOL_VERSION);
    commit_tx.vout.front().nValue = CalculateOutputAmount(*m_ord_amount, m_mining_fee_rate.value(), tx_size);

    m_ord_utxo_sig = keypair.SignTaprootTx(commit_tx, 0, {CTxOut(*m_ord_amount, utxo_pubkeyscript)}, {});

    commit_tx.vin.front().scriptWitness.stack.front() = static_cast<bytevector&>(*m_ord_utxo_sig);

    mOrdCommitTx = commit_tx;
}

void SwapInscriptionBuilder::SignOrdPayBack(std::string sk)
{
    core::ChannelKeys keypair(unhex<seckey>(sk));

    auto commit_taproot = OrdCommitTapRoot();

    CScript commit_pubkeyscript;
    commit_pubkeyscript << 1;
    commit_pubkeyscript << get<0>(commit_taproot);

    CScript payoff_pubkeyscript;
    payoff_pubkeyscript << 1;
    payoff_pubkeyscript << m_swap_script_pk_A.value();

    xonly_pubkey internal_unspendable_key = core::ChannelKeys::CreateUnspendablePubKey(m_ord_unspendable_key_factor.value());

    CScript& payoff_script = get<2>(commit_taproot).GetScripts()[1];

    auto commit_scriptpath = get<2>(commit_taproot).CalculateScriptPath(payoff_script);
    bytevector control_block = {static_cast<uint8_t>(0xc0 | get<1>(commit_taproot))};
    control_block.reserve(1 + internal_unspendable_key.size() + commit_scriptpath.size() * uint256::size());
    control_block.insert(control_block.end(), internal_unspendable_key.begin(), internal_unspendable_key.end());
    for(uint256 &branch_hash : commit_scriptpath)
        control_block.insert(control_block.end(), branch_hash.begin(), branch_hash.end());

    CMutableTransaction payoff_tx;
    payoff_tx.vin = {CTxIn(mOrdCommitTx->GetHash(), 0, {}, GetCsvInBlocks(12))};
    payoff_tx.vout = {CTxOut(m_ord_amount.value(), payoff_pubkeyscript)};
    payoff_tx.vin.front().scriptWitness.stack.emplace_back(64);
    payoff_tx.vin.front().scriptWitness.stack.emplace_back(payoff_script.begin(), payoff_script.end());
    payoff_tx.vin.front().scriptWitness.stack.emplace_back(control_block);

    size_t tx_size = GetSerializeSize(payoff_tx, PROTOCOL_VERSION);
    payoff_tx.vout.front().nValue = CalculateOutputAmount(*m_ord_amount, m_mining_fee_rate.value(), tx_size);

    signature payoff_sig = keypair.SignTaprootTx(payoff_tx, 0, {mOrdCommitTx->vout[0]}, payoff_script);

    payoff_tx.vin.front().scriptWitness.stack.front() = move(payoff_sig);

    mOrdPayOffTx = move(payoff_tx);
}


void SwapInscriptionBuilder::SignFundsCommitment(std::string sk)
{
    core::ChannelKeys keypair(unhex<seckey>(sk));
    m_funds_utxo_pk = keypair.GetLocalPubKey();

    CScript utxo_pubkeyscript;
    utxo_pubkeyscript << 1;
    utxo_pubkeyscript << *m_funds_utxo_pk;

    CScript commit_pubkeyscript;
    commit_pubkeyscript << 1;
    commit_pubkeyscript << get<0>(FundsCommitTapRoot());

    CMutableTransaction commit_tx;
    commit_tx.vin = {CTxIn(COutPoint(uint256S(m_funds_txid.value()), m_funds_nout.value()))};
    commit_tx.vout = {CTxOut(m_funds_amount.value(), commit_pubkeyscript)};
    commit_tx.vin.front().scriptWitness.stack.emplace_back(64);

    size_t tx_size = GetSerializeSize(commit_tx, PROTOCOL_VERSION);
    commit_tx.vout.front().nValue = CalculateOutputAmount(*m_funds_amount, m_mining_fee_rate.value(), tx_size);

    m_funds_utxo_sig = keypair.SignTaprootTx(commit_tx, 0, {CTxOut(*m_funds_amount, utxo_pubkeyscript)}, {});

    commit_tx.vin.front().scriptWitness.stack.front() = static_cast<bytevector&>(*m_funds_utxo_sig);

    mFundsCommitTx = commit_tx;
}

void SwapInscriptionBuilder::SignFundsPayBack(std::string sk)
{
    core::ChannelKeys keypair(unhex<seckey>(sk));

    auto commit_taproot = FundsCommitTapRoot();

    CScript commit_pubkeyscript;
    commit_pubkeyscript << 1;
    commit_pubkeyscript << get<0>(commit_taproot);

    CScript payoff_pubkeyscript;
    payoff_pubkeyscript << 1;
    payoff_pubkeyscript << m_swap_script_pk_B.value();

    xonly_pubkey internal_unspendable_key = core::ChannelKeys::CreateUnspendablePubKey(m_funds_unspendable_key_factor.value());

    CScript& payoff_script = get<2>(commit_taproot).GetScripts()[1];

    auto commit_scriptpath = get<2>(commit_taproot).CalculateScriptPath(payoff_script);
    bytevector control_block = {static_cast<uint8_t>(0xc0 | get<1>(commit_taproot))};
    control_block.reserve(1 + internal_unspendable_key.size() + commit_scriptpath.size() * uint256::size());
    control_block.insert(control_block.end(), internal_unspendable_key.begin(), internal_unspendable_key.end());
    for(uint256 &branch_hash : commit_scriptpath)
        control_block.insert(control_block.end(), branch_hash.begin(), branch_hash.end());

    CMutableTransaction payoff_tx;
    payoff_tx.vin = {CTxIn(mFundsCommitTx->GetHash(), 0, {}, GetCsvInBlocks(12))};
    payoff_tx.vout = {CTxOut(m_funds_amount.value(), payoff_pubkeyscript)};
    payoff_tx.vin.front().scriptWitness.stack.emplace_back(64);
    payoff_tx.vin.front().scriptWitness.stack.emplace_back(payoff_script.begin(), payoff_script.end());
    payoff_tx.vin.front().scriptWitness.stack.emplace_back(control_block);

    size_t tx_size = GetSerializeSize(payoff_tx, PROTOCOL_VERSION);
    payoff_tx.vout.front().nValue = CalculateOutputAmount(*m_funds_amount, m_mining_fee_rate.value(), tx_size);

    signature payoff_sig = keypair.SignTaprootTx(payoff_tx, 0, {mFundsCommitTx->vout[0]}, payoff_script);

    payoff_tx.vin.front().scriptWitness.stack.front() = move(payoff_sig);

    mFundsPayOffTx = move(payoff_tx);
}

string SwapInscriptionBuilder::OrdCommitRawTransaction() const
{
    if (!mOrdCommitTx) {
        throw std::logic_error("OrdCommit transaction data unavailable");
    }
    std::string res = EncodeHexTx(CTransaction(*mOrdCommitTx));
    return res;
}

string SwapInscriptionBuilder::OrdPayBackRawTransaction() const
{
    if (!mOrdPayOffTx) {
        throw std::logic_error("OrdPayOff transaction data unavailable");
    }
    std::string res = EncodeHexTx(CTransaction(*mOrdPayOffTx));
    return res;
}

string SwapInscriptionBuilder::FundsCommitRawTransaction() const
{
    if (!mFundsCommitTx) {
        throw std::logic_error("FundsCommit transaction data unavailable");
    }
    std::string res = EncodeHexTx(CTransaction(*mFundsCommitTx));
    return res;
}

string SwapInscriptionBuilder::FundsPayBackRawTransaction() const
{
    if (!mFundsPayOffTx) {
        throw std::logic_error("FundsPayOff transaction data unavailable");
    }
    std::string res = EncodeHexTx(CTransaction(*mFundsPayOffTx));
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
