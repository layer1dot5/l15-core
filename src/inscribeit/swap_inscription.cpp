#include "swap_inscription.hpp"

#include "univalue.h"

#include "core_io.h"

#include "channel_keys.hpp"


namespace l15::inscribeit {

namespace {

const std::string val_swap_inscription("SwapInscription");

const uint32_t COMMIT_TIMEOUT = 12;

CScript MakeOrdSwapScript(const xonly_pubkey& pk_A, const xonly_pubkey& pk_M)
{
    CScript script;
    script << pk_A << OP_CHECKSIG;
    script << pk_M << OP_CHECKSIGADD;
    script << 2 << OP_NUMEQUAL;
    return script;
}

CScript MakeFundsSwapScript(const xonly_pubkey& pk_B, const xonly_pubkey& pk_M)
{
    CScript script;
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

}

const uint32_t SwapInscriptionBuilder::m_protocol_version = 1;

const std::string SwapInscriptionBuilder::name_ord_price = "ord_price";
const std::string SwapInscriptionBuilder::name_market_fee = "market_fee";

const std::string SwapInscriptionBuilder::name_swap_script_pk_A = "swap_script_pk_A";
const std::string SwapInscriptionBuilder::name_swap_script_pk_B = "swap_script_pk_B";
const std::string SwapInscriptionBuilder::name_swap_script_pk_M = "swap_script_pk_M";

const std::string SwapInscriptionBuilder::name_ord_unspendable_key_factor = "ord_unspendable_key_factor";
const std::string SwapInscriptionBuilder::name_ord_txid = "ord_txid";
const std::string SwapInscriptionBuilder::name_ord_nout = "ord_nout";
const std::string SwapInscriptionBuilder::name_ord_amount = "ord_amount";

const std::string SwapInscriptionBuilder::name_ord_commit_mining_fee_rate = "ord_commit_mining_fee_rate";
const std::string SwapInscriptionBuilder::name_ord_commit_sig = "ord_utxo_sig";

const std::string SwapInscriptionBuilder::name_funds_unspendable_key_factor = "funds_unspendable_key_factor";
const std::string SwapInscriptionBuilder::name_funds_txid = "funds_txid";
const std::string SwapInscriptionBuilder::name_funds_nout = "funds_nout";
const std::string SwapInscriptionBuilder::name_funds_amount = "funds_amount";

const std::string SwapInscriptionBuilder::name_funds_commit_sig = "funds_commit_sig";

const std::string SwapInscriptionBuilder::name_ord_swap_sig_A = "ord_swap_sig_A";
const std::string SwapInscriptionBuilder::name_ord_swap_sig_M = "ord_swap_sig_M";
const std::string SwapInscriptionBuilder::name_funds_swap_sig_B = "funds_swap_sig_B";
const std::string SwapInscriptionBuilder::name_funds_swap_sig_M = "funds_swap_sig_M";

const std::string SwapInscriptionBuilder::name_ordpayoff_unspendable_key_factor = "ordpayoff_unspendable_key_factor";
const std::string SwapInscriptionBuilder::name_ordpayoff_sig = "ordpayoff_sig";


SwapInscriptionBuilder::SwapInscriptionBuilder(const string &chain_mode, const string &ord_price, const string &market_fee)
        : ContractBuilder(chain_mode), m_ord_price(ParseAmount(ord_price)), m_market_fee(ParseAmount(market_fee)) {};


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
                              { MakeFundsSwapScript(m_swap_script_pk_B.value(), m_swap_script_pk_M.value()),
                                MakeRelTimeLockScript(COMMIT_TIMEOUT, m_swap_script_pk_B.value())});

    return std::tuple_cat(core::ChannelKeys::AddTapTweak(core::ChannelKeys::CreateUnspendablePubKey(m_funds_unspendable_key_factor.value()),
                                                  tap_tree.CalculateRoot()), std::make_tuple(tap_tree));
}


void SwapInscriptionBuilder::SignOrdCommitment(std::string sk)
{
    CheckContractTerms(OrdTerms);

    core::ChannelKeys keypair(unhex<seckey>(sk));
    const xonly_pubkey& ord_utxo_pk = keypair.GetLocalPubKey();
    m_ord_unspendable_key_factor = core::ChannelKeys::GetStrongRandomKey(keypair.Secp256k1Context());

    auto utxo_pubkeyscript = CScript() << 1 << (ord_utxo_pk);
    auto commit_pubkeyscript = CScript() << 1 << get<0>(OrdCommitTapRoot());

    CMutableTransaction commit_tx;
    commit_tx.vin = {CTxIn(COutPoint(uint256S(*m_ord_txid), *m_ord_nout))};
    commit_tx.vin.front().scriptWitness.stack.emplace_back(64);
    commit_tx.vout = {CTxOut(*m_ord_amount, commit_pubkeyscript)};
    commit_tx.vout.front().nValue = CalculateOutputAmount(*m_ord_amount, *m_ord_commit_mining_fee_rate, commit_tx);

    m_ord_commit_sig = keypair.SignTaprootTx(commit_tx, 0, {CTxOut(*m_ord_amount, utxo_pubkeyscript)}, {});
    commit_tx.vin.front().scriptWitness.stack.front() = static_cast<bytevector&>(*m_ord_commit_sig);

    mOrdCommitTx = move(commit_tx);
}

CMutableTransaction SwapInscriptionBuilder::MakeSwapTx(bool with_funds_in)
{
    auto ord_commit_taproot = OrdCommitTapRoot();

    auto ord_pubkeyscript = CScript() << 1 << *m_swap_script_pk_M;
    auto funds_pubkeyscript = CScript() << 1 << *m_swap_script_pk_A;
    auto fee_pubkeyscript = CScript() << 1 << *m_swap_script_pk_M;

    xonly_pubkey ord_unspendable_key = core::ChannelKeys::CreateUnspendablePubKey(*m_ord_unspendable_key_factor);

    CScript& ord_swap_script = get<2>(ord_commit_taproot).GetScripts()[0];

    auto ord_scriptpath = get<2>(ord_commit_taproot).CalculateScriptPath(ord_swap_script);
    bytevector ord_control_block = {static_cast<uint8_t>(0xc0 | get<1>(ord_commit_taproot))};
    ord_control_block.reserve(1 + ord_unspendable_key.size() + ord_scriptpath.size() * uint256::size());
    ord_control_block.insert(ord_control_block.end(), ord_unspendable_key.begin(), ord_unspendable_key.end());
    for(uint256 &branch_hash : ord_scriptpath)
        ord_control_block.insert(ord_control_block.end(), branch_hash.begin(), branch_hash.end());

    CMutableTransaction swap_tx;
    swap_tx.vin = {CTxIn(GetOrdCommitTx().GetHash(), 0)};
    if (m_ord_swap_sig_M) {
        swap_tx.vin.front().scriptWitness.stack.push_back(*m_ord_swap_sig_M);
    } else {
        swap_tx.vin.front().scriptWitness.stack.emplace_back(64);
    }
    if (m_ord_swap_sig_A) {
        swap_tx.vin.front().scriptWitness.stack.push_back(*m_ord_swap_sig_A);
    } else {
        swap_tx.vin.front().scriptWitness.stack.emplace_back(65);
    }
    swap_tx.vin.front().scriptWitness.stack.emplace_back(ord_swap_script.begin(), ord_swap_script.end());
    swap_tx.vin.front().scriptWitness.stack.emplace_back(move(ord_control_block));
    swap_tx.vout = {CTxOut(*m_ord_amount, ord_pubkeyscript),
                    CTxOut(m_ord_price, funds_pubkeyscript),
                    CTxOut(*m_market_fee, fee_pubkeyscript)};

    if (with_funds_in) {
        auto funds_commit_taproot = FundsCommitTapRoot();

        xonly_pubkey funds_unspendable_key = core::ChannelKeys::CreateUnspendablePubKey(*m_funds_unspendable_key_factor);

        CScript& funds_swap_script = get<2>(funds_commit_taproot).GetScripts()[0];

        auto funds_scriptpath = get<2>(funds_commit_taproot).CalculateScriptPath(funds_swap_script);
        bytevector funds_control_block = {static_cast<uint8_t>(0xc0 | get<1>(funds_commit_taproot))};
        funds_control_block.reserve(1 + funds_unspendable_key.size() + funds_scriptpath.size() * uint256::size());
        funds_control_block.insert(funds_control_block.end(), funds_unspendable_key.begin(), funds_unspendable_key.end());
        for(uint256 &branch_hash : funds_scriptpath)
            funds_control_block.insert(funds_control_block.end(), branch_hash.begin(), branch_hash.end());

        swap_tx.vin.emplace_back(mFundsCommitTx->GetHash(), 0);
        if (m_funds_swap_sig_M) {
            swap_tx.vin.back().scriptWitness.stack.push_back(*m_funds_swap_sig_M);
        } else {
            swap_tx.vin.back().scriptWitness.stack.emplace_back(64);
        }
        if (m_funds_swap_sig_B) {
            swap_tx.vin.back().scriptWitness.stack.push_back(*m_funds_swap_sig_B);
        } else {
            swap_tx.vin.back().scriptWitness.stack.emplace_back(64);
        }
        swap_tx.vin.back().scriptWitness.stack.emplace_back(funds_swap_script.begin(), funds_swap_script.end());
        swap_tx.vin.back().scriptWitness.stack.emplace_back(move(funds_control_block));
    }

    return swap_tx;
}

void SwapInscriptionBuilder::SignOrdSwap(std::string sk)
{
    const CMutableTransaction& ord_commit = GetOrdCommitTx(); // Request it here in order to force reuired fields check

    core::ChannelKeys keypair(unhex<seckey>(sk));

    if (keypair.GetLocalPubKey() != *m_swap_script_pk_A) {
        throw ContractError("Swap PubKey does not match the secret");
    }

    CMutableTransaction swap_tx(MakeSwapTx(false));

    m_ord_swap_sig_A = keypair.SignTaprootTx(swap_tx, 0, {ord_commit.vout[0]}, MakeOrdSwapScript(*m_swap_script_pk_A, *m_swap_script_pk_M), SIGHASH_ALL|SIGHASH_ANYONECANPAY);
}


void SwapInscriptionBuilder::SignOrdPayBack(std::string sk)
{
    const CMutableTransaction& ord_commit = GetOrdCommitTx(); // Request it here in order to force reuired fields check

    core::ChannelKeys keypair(unhex<seckey>(sk));

    if (keypair.GetLocalPubKey() != *m_swap_script_pk_A) {
        throw ContractError("Swap PubKey does not match the secret");
    }

    auto commit_taproot = OrdCommitTapRoot();

    auto payoff_pubkeyscript = CScript() << 1 << *m_swap_script_pk_A;

    xonly_pubkey internal_unspendable_key = core::ChannelKeys::CreateUnspendablePubKey(*m_ord_unspendable_key_factor);

    CScript& payoff_script = get<2>(commit_taproot).GetScripts()[1];

    auto commit_scriptpath = get<2>(commit_taproot).CalculateScriptPath(payoff_script);
    bytevector control_block = {static_cast<uint8_t>(0xc0 | get<1>(commit_taproot))};
    control_block.reserve(1 + internal_unspendable_key.size() + commit_scriptpath.size() * uint256::size());
    control_block.insert(control_block.end(), internal_unspendable_key.begin(), internal_unspendable_key.end());
    for(uint256 &branch_hash : commit_scriptpath)
        control_block.insert(control_block.end(), branch_hash.begin(), branch_hash.end());

    CMutableTransaction payback_tx;
    payback_tx.vin = {CTxIn(ord_commit.GetHash(), 0, {}, GetCsvInBlocks(12))};
    payback_tx.vin.front().scriptWitness.stack.emplace_back(64);
    payback_tx.vin.front().scriptWitness.stack.emplace_back(payoff_script.begin(), payoff_script.end());
    payback_tx.vin.front().scriptWitness.stack.emplace_back(control_block);
    payback_tx.vout = {CTxOut(m_ord_amount.value(), payoff_pubkeyscript)};
    payback_tx.vout.front().nValue = CalculateOutputAmount(ord_commit.vout[0].nValue, *m_ord_commit_mining_fee_rate, payback_tx);

    signature payoff_sig = keypair.SignTaprootTx(payback_tx, 0, {ord_commit.vout[0]}, payoff_script);
    payback_tx.vin.front().scriptWitness.stack.front() = move(payoff_sig);

    mOrdPaybackTx = move(payback_tx);
}

void SwapInscriptionBuilder::SignFundsCommitment(std::string sk)
{
    CheckContractTerms(FundsTerms);

    core::ChannelKeys keypair(unhex<seckey>(sk));
    const xonly_pubkey& funds_utxo_pk = keypair.GetLocalPubKey();
    m_funds_unspendable_key_factor = core::ChannelKeys::GetStrongRandomKey(keypair.Secp256k1Context());

    auto utxo_pubkeyscript = CScript() << 1 << funds_utxo_pk;
    auto commit_pubkeyscript = CScript() << 1 << get<0>(FundsCommitTapRoot());

    CMutableTransaction commit_tx;
    commit_tx.vin = {CTxIn(COutPoint(uint256S(m_funds_txid.value()), m_funds_nout.value()))};
    commit_tx.vin.front().scriptWitness.stack.emplace_back(64);
    commit_tx.vout = {CTxOut(m_funds_amount.value(), commit_pubkeyscript)};
    commit_tx.vout.front().nValue = CalculateOutputAmount(*m_funds_amount, *m_mining_fee_rate, commit_tx);

    m_funds_commit_sig = keypair.SignTaprootTx(commit_tx, 0, {CTxOut(*m_funds_amount, utxo_pubkeyscript)}, {});
    commit_tx.vin.front().scriptWitness.stack.front() = static_cast<bytevector&>(*m_funds_commit_sig);

    mFundsCommitTx = move(commit_tx);
}


void SwapInscriptionBuilder::SignFundsSwap(std::string sk)
{
    CheckContractTerms(MarketPayoffSig);

    core::ChannelKeys keypair(unhex<seckey>(sk));

    if (keypair.GetLocalPubKey() != *m_swap_script_pk_B) {
        throw ContractError("Swap PubKey does not match the secret");
    }

    const CMutableTransaction& ord_commit = GetOrdCommitTx();
    const CMutableTransaction& funds_commit = GetFundsCommitTx();
    CMutableTransaction swap_tx(MakeSwapTx(true));

    m_funds_swap_sig_B = keypair.SignTaprootTx(swap_tx, 1, {ord_commit.vout[0], funds_commit.vout[0]}, MakeFundsSwapScript(*m_swap_script_pk_B, *m_swap_script_pk_M));
}

void SwapInscriptionBuilder::SignFundsPayBack(std::string sk)
{
    const CMutableTransaction& funds_commit = GetFundsCommitTx(); // Request it here in order to force reuired fields check

    core::ChannelKeys keypair(unhex<seckey>(sk));

    auto commit_taproot = FundsCommitTapRoot();
    auto commit_pubkeyscript = CScript() << 1 << get<0>(commit_taproot);
    auto payoff_pubkeyscript = CScript() << 1 << *m_swap_script_pk_B;

    xonly_pubkey internal_unspendable_key = core::ChannelKeys::CreateUnspendablePubKey(*m_funds_unspendable_key_factor);

    CScript& payback_script = get<2>(commit_taproot).GetScripts()[1];

    auto commit_scriptpath = get<2>(commit_taproot).CalculateScriptPath(payback_script);
    bytevector control_block = {static_cast<uint8_t>(0xc0 | get<1>(commit_taproot))};
    control_block.reserve(1 + internal_unspendable_key.size() + commit_scriptpath.size() * uint256::size());
    control_block.insert(control_block.end(), internal_unspendable_key.begin(), internal_unspendable_key.end());
    for(uint256 &branch_hash : commit_scriptpath)
        control_block.insert(control_block.end(), branch_hash.begin(), branch_hash.end());

    CMutableTransaction payback_tx;
    payback_tx.vin = {CTxIn(funds_commit.GetHash(), 0, {}, GetCsvInBlocks(12))};
    payback_tx.vin.front().scriptWitness.stack.emplace_back(64);
    payback_tx.vin.front().scriptWitness.stack.emplace_back(payback_script.begin(), payback_script.end());
    payback_tx.vin.front().scriptWitness.stack.emplace_back(control_block);
    payback_tx.vout = {CTxOut(*m_funds_amount, payoff_pubkeyscript)};
    payback_tx.vout.front().nValue = CalculateOutputAmount(funds_commit.vout[0].nValue, *m_mining_fee_rate, payback_tx);

    signature payback_sig = keypair.SignTaprootTx(payback_tx, 0, {funds_commit.vout[0]}, payback_script);
    payback_tx.vin.front().scriptWitness.stack.front() = move(payback_sig);

    mFundsPaybackTx = move(payback_tx);
}

void SwapInscriptionBuilder::MarketSignOrdPayoffTx(std::string sk)
{
    CheckContractTerms(MarketPayoffTerms);

    core::ChannelKeys keypair(unhex<seckey>(sk));
    if (keypair.GetLocalPubKey() != *m_swap_script_pk_M) {
        throw ContractError("Swap PubKey does not match the secret");
    }

    CScript transfer_pubkeyscript = CScript() << 1 << *m_swap_script_pk_B;

    CMutableTransaction swap_tx(MakeSwapTx(true));

    CMutableTransaction transfer_tx;

    transfer_tx.vin = {CTxIn(swap_tx.GetHash(), 0)};
    transfer_tx.vin.front().scriptWitness.stack.emplace_back(64);
    transfer_tx.vout = {CTxOut(swap_tx.vout[0].nValue, move(transfer_pubkeyscript))};
    transfer_tx.vout.front().nValue = CalculateOutputAmount(swap_tx.vout[0].nValue, *m_mining_fee_rate, transfer_tx);

    m_ordpayoff_sig = keypair.SignTaprootTx(transfer_tx, 0, {swap_tx.vout[0]}, {});

    transfer_tx.vin.front().scriptWitness.stack.front() = *m_ordpayoff_sig;

    mOrdPayoffTx = move(transfer_tx);
}

void SwapInscriptionBuilder::MarketSignSwap(std::string sk)
{
    CheckContractTerms(OrdSwapSig);
    CheckContractTerms(FundsSwapSig);

    core::ChannelKeys keypair(unhex<seckey>(sk));

    if (keypair.GetLocalPubKey() != m_swap_script_pk_M.value()) {
        throw ContractError("Swap PubKey does not match the secret");
    }

    CMutableTransaction swap_tx(MakeSwapTx(true));

    m_ord_swap_sig_M = keypair.SignTaprootTx(swap_tx, 0, {GetOrdCommitTx().vout[0], GetFundsCommitTx().vout[0]}, MakeOrdSwapScript(*m_swap_script_pk_A, *m_swap_script_pk_M));
    m_funds_swap_sig_M = keypair.SignTaprootTx(swap_tx, 1, {GetOrdCommitTx().vout[0], GetFundsCommitTx().vout[0]}, MakeFundsSwapScript(*m_swap_script_pk_B, *m_swap_script_pk_M));

    swap_tx.vin[0].scriptWitness.stack[0] = *m_ord_swap_sig_M;
    swap_tx.vin[1].scriptWitness.stack[0] = *m_funds_swap_sig_M;

    mSwapTx = move(swap_tx);
}

string SwapInscriptionBuilder::OrdCommitRawTransaction()
{
    std::string res = EncodeHexTx(CTransaction(GetOrdCommitTx()));
    return res;
}

string SwapInscriptionBuilder::OrdPayBackRawTransaction()
{
    if (!mOrdPaybackTx) {
        throw std::logic_error("OrdPayOff transaction data unavailable");
    }
    std::string res = EncodeHexTx(CTransaction(*mOrdPaybackTx));
    return res;
}

string SwapInscriptionBuilder::FundsCommitRawTransaction()
{
    std::string res = EncodeHexTx(CTransaction(GetFundsCommitTx()));
    return res;
}

string SwapInscriptionBuilder::FundsPayBackRawTransaction()
{
    if (!mFundsPaybackTx) {
        throw std::logic_error("FundsPayOff transaction data unavailable");
    }
    std::string res = EncodeHexTx(CTransaction(*mFundsPaybackTx));
    return res;
}

string SwapInscriptionBuilder::OrdSwapRawTransaction()
{
    std::string res = EncodeHexTx(CTransaction(GetSwapTx()));
    return res;
}

string SwapInscriptionBuilder::OrdPayoffRawTransaction()
{
    std::string res = EncodeHexTx(CTransaction(GetPayoffTx()));
    return res;
}

string SwapInscriptionBuilder::Serialize(SwapPhase phase)
{
    CheckContractTerms(phase);

    UniValue contract(UniValue::VOBJ);

    contract.pushKV(name_version, m_protocol_version);
    contract.pushKV(name_ord_price, UniValue(UniValue::VNUM, FormatAmount(m_ord_price)));
    contract.pushKV(name_swap_script_pk_M, hex(*m_swap_script_pk_M));

    if (phase == OrdTerms || phase == OrdCommitSig || phase == OrdSwapSig || phase == MarketPayoffSig || phase == MarketSwapSig) {
        contract.pushKV(name_ord_commit_mining_fee_rate, UniValue(UniValue::VNUM, FormatAmount(*m_ord_commit_mining_fee_rate)));
    }
    if (phase == OrdCommitSig || phase == OrdSwapSig || phase == MarketPayoffSig || phase == MarketSwapSig) {
        contract.pushKV(name_ord_txid, *m_ord_txid);
        contract.pushKV(name_ord_nout, *m_ord_nout);
        contract.pushKV(name_ord_amount, UniValue(UniValue::VNUM, FormatAmount(*m_ord_amount)));
        contract.pushKV(name_ord_unspendable_key_factor, hex(*m_ord_unspendable_key_factor));
        contract.pushKV(name_swap_script_pk_A, hex(*m_swap_script_pk_A));
        contract.pushKV(name_ord_commit_sig, hex(*m_ord_commit_sig));
    }
    if (phase == OrdSwapSig || phase == MarketPayoffSig || phase == MarketSwapSig) {
        contract.pushKV(name_ord_swap_sig_A, hex(*m_ord_swap_sig_A));
    }

    if (phase == FundsTerms || phase == FundsCommitSig || phase == MarketPayoffSig || phase == FundsSwapSig || phase == MarketSwapSig) {
        contract.pushKV(name_market_fee, UniValue(UniValue::VNUM, FormatAmount(*m_market_fee)));
        contract.pushKV(name_mining_fee_rate, UniValue(UniValue::VNUM, FormatAmount(*m_mining_fee_rate)));
    }
    if (phase == FundsCommitSig || phase == MarketPayoffSig || phase == FundsSwapSig || phase == MarketSwapSig) {
        contract.pushKV(name_funds_txid, *m_funds_txid);
        contract.pushKV(name_funds_nout, *m_funds_nout);
        contract.pushKV(name_funds_amount, UniValue(UniValue::VNUM, FormatAmount(*m_funds_amount)));
        contract.pushKV(name_funds_unspendable_key_factor, hex(*m_funds_unspendable_key_factor));
        contract.pushKV(name_swap_script_pk_B, hex(*m_swap_script_pk_B));
        contract.pushKV(name_funds_commit_sig, hex(*m_funds_commit_sig));
    }

    if (phase == MarketPayoffSig) {
        contract.pushKV(name_ordpayoff_sig, hex(*m_ordpayoff_sig));
    }

    if (phase == FundsSwapSig || phase == MarketSwapSig) {
        contract.pushKV(name_funds_swap_sig_B, hex(*m_funds_swap_sig_B));
    }

    if (phase == MarketSwapSig) {
        contract.pushKV(name_funds_swap_sig_M, hex(*m_funds_swap_sig_M));
    }

    UniValue dataRoot(UniValue::VOBJ);
    dataRoot.pushKV(name_contract_type, val_swap_inscription);
    dataRoot.pushKV(name_params, contract);

    return dataRoot.write();
}

void SwapInscriptionBuilder::CheckContractTerms(SwapInscriptionBuilder::SwapPhase phase)
{
    switch (phase) {
    case MarketSwapSig:
        if (!m_ord_swap_sig_M) throw ContractTermMissing("Market ord sig");
        if (!m_funds_swap_sig_M) throw ContractTermMissing("Market funds sig");
        // no break;
    case FundsSwapSig:
        if (!m_funds_swap_sig_B) throw ContractTermMissing("Funds seller sig");
        // no break;
    case MarketPayoffSig:
        if (!m_ordpayoff_sig) throw ContractTermMissing("Ord pay-off sig");
        // no break;
    case MarketPayoffTerms:
        CheckContractTerms(FundsCommitSig);
    case OrdSwapSig:
        if (!m_ord_swap_sig_A) throw ContractTermMissing("Ord seller sig");
        // no break;
    case OrdCommitSig:
        if (!m_ord_amount) throw ContractTermMissing("Ord UTXO amount");
        if (!m_ord_txid) throw ContractTermMissing("Ord UTXO txid");
        if (!m_ord_nout) throw ContractTermMissing("Ord UTXO nout");
        if (!m_ord_unspendable_key_factor) throw ContractTermMissing("Ord commit unspendable key factor");
        if (!m_swap_script_pk_A) throw ContractTermMissing("Ord seller pubkey");
        if (!m_ord_commit_sig) throw ContractTermMissing("Ord commit sig");
        // no break;
    case OrdTerms:
        if (m_ord_price <= 0) throw ContractTermMissing("Ord price");
        if (!m_ord_commit_mining_fee_rate) throw ContractTermMissing("Ord commit mining fee rate");
        if (!m_swap_script_pk_M) throw ContractTermMissing("Market swap pubkey");
        break;
    case FundsCommitSig:
        if (!m_funds_amount) throw ContractTermMissing("Funds UTXO amount");
        if (*m_funds_amount < (m_ord_price + *m_market_fee)) throw ContractTermMissing("Funds UTXO amount too small");
        if (!m_funds_txid) throw ContractTermMissing("Funds UTXO txid");
        if (!m_funds_nout) throw ContractTermMissing("Funds UTXO nout");
        if (!m_swap_script_pk_B) throw ContractTermMissing("Ord buyer pubkey");
        if (!m_funds_unspendable_key_factor) throw ContractTermMissing("Funds commit unspendable key factor");
        if (!m_funds_commit_sig) throw ContractTermMissing("Funds commit sig");
        // no break;
    case FundsTerms:
        if (m_ord_price <= 0) throw ContractTermMissing("Ord price");
        if (!m_market_fee) throw ContractTermMissing("Market fee");
        if (!m_mining_fee_rate) throw ContractTermMissing("Mining fee rate");
        if (!m_swap_script_pk_M) throw ContractTermMissing("Market pubkey");
        break;
    }
}

void SwapInscriptionBuilder::Deserialize(const string& data)
{
    UniValue dataRoot;
    dataRoot.read(data);

    if (dataRoot[name_contract_type].get_str() != val_swap_inscription) {
        throw ContractProtocolError("SwapInscription contract does not match " + dataRoot[name_contract_type].getValStr());
    }

    UniValue contract = dataRoot[name_params];

    if (contract[name_version].getInt<uint32_t>() != m_protocol_version) {
        throw ContractProtocolError("Wrong SwapInscription contract version: " + contract[name_version].getValStr());
    }

    if (m_ord_price) {
        if (m_ord_price != ParseAmount(contract[name_ord_price].getValStr())) throw ContractError(std::string(name_ord_price));
    } else
        m_ord_price = ParseAmount(contract[name_ord_price].getValStr());

    {   const auto &val = contract[name_market_fee];
        if (!val.isNull()) {
            if (m_market_fee) {
                if (*m_market_fee != ParseAmount(val.getValStr())) throw ContractError(std::string(name_market_fee));
            }
            m_market_fee = ParseAmount(val.getValStr());
        }
    }
    {   const auto& val = contract[name_swap_script_pk_A];
        if (!val.isNull()) {
            if (m_swap_script_pk_A) {
                if (*m_swap_script_pk_A != unhex<xonly_pubkey>(val.get_str())) throw ContractError("swap_script_pk_A");
            }
            else m_swap_script_pk_A = unhex<xonly_pubkey>(val.get_str());
        }
    }
    {   const auto& val = contract[name_swap_script_pk_B];
        if (!val.isNull()) {
            if (m_swap_script_pk_B) {
                if (*m_swap_script_pk_B != unhex<xonly_pubkey>(val.get_str())) throw ContractError("swap_script_pk_B");
            }
            else m_swap_script_pk_B = unhex<xonly_pubkey>(val.get_str());
        }
    }
    {   const auto& val = contract[name_swap_script_pk_M];
        if (!val.isNull()) {
            if (m_swap_script_pk_M) {
                if (*m_swap_script_pk_M != unhex<xonly_pubkey>(val.get_str())) throw ContractError("swap_script_pk_M");
            }
            else m_swap_script_pk_M = unhex<xonly_pubkey>(val.get_str());
        }
    }
    {   const auto& val = contract[name_ord_unspendable_key_factor];
        if (!val.isNull()) {
            if (m_ord_unspendable_key_factor) {
                if (*m_ord_unspendable_key_factor != unhex<seckey>(val.get_str())) throw ContractError(std::string(name_ord_unspendable_key_factor));
            }
            else m_ord_unspendable_key_factor = unhex<seckey>(val.get_str());
        }
    }
    {   const auto& val = contract[name_ord_txid];
        if (!val.isNull()) {
            if (m_ord_txid) {
                if (*m_ord_txid != val.get_str()) throw ContractError(std::string(name_ord_txid));
            }
            else m_ord_txid = val.get_str();
        }
    }
    {   const auto& val = contract[name_ord_nout];
        if (!val.isNull()) {
            if (m_ord_nout) {
                if (*m_ord_nout != val.getInt<uint32_t>()) throw ContractError(std::string(name_ord_nout));
            }
            else m_ord_nout = val.getInt<uint32_t>();
        }
    }
    {   const auto& val = contract[name_ord_amount];
        if (!val.isNull()) {
            if (m_ord_amount) {
                if (*m_ord_amount != ParseAmount(val.getValStr())) throw ContractError(std::string(name_ord_amount));
            }
            else m_ord_amount = ParseAmount(val.getValStr());
        }
    }
    {   const auto& val = contract[name_ord_commit_mining_fee_rate];
        if (!val.isNull()) {
            if (m_ord_commit_mining_fee_rate) {
                if (*m_ord_commit_mining_fee_rate != ParseAmount(val.getValStr())) throw ContractError(std::string(name_ord_commit_mining_fee_rate));
            }
            else m_ord_commit_mining_fee_rate = ParseAmount(val.getValStr());
        }
    }
    {   const auto& val = contract[name_ord_commit_sig];
        if (!val.isNull()) {
            if (m_ord_commit_sig) {
                if (*m_ord_commit_sig != unhex<signature>(val.get_str())) throw ContractError(std::string(name_ord_commit_sig));
            }
            else m_ord_commit_sig = unhex<signature>(val.get_str());
        }
    }

    {   const auto& val = contract[name_funds_unspendable_key_factor];
        if (!val.isNull()) {
            if (m_funds_unspendable_key_factor) {
                if (*m_funds_unspendable_key_factor != unhex<seckey>(val.get_str())) throw ContractError(std::string(name_funds_unspendable_key_factor));
            }
            else m_funds_unspendable_key_factor = unhex<seckey>(val.get_str());
        }
    }
    {   const auto& val = contract[name_funds_txid];
        if (!val.isNull()) {
            if (m_funds_txid) {
                if (*m_funds_txid != val.get_str()) throw ContractError(std::string(name_funds_txid));
            }
            else m_funds_txid = val.get_str();
        }
    }
    {   const auto& val = contract[name_funds_nout];
        if (!val.isNull()) {
            if (m_funds_nout) {
                if (*m_funds_nout != val.getInt<uint32_t>()) throw ContractError(std::string(name_funds_nout));
            }
            else m_funds_nout = val.getInt<uint32_t>();
        }
    }
    {   const auto& val = contract[name_funds_amount];
        if (!val.isNull()) {
            if (m_funds_amount) {
                if (*m_funds_amount != ParseAmount(val.getValStr())) throw ContractError(std::string(name_funds_amount));
            }
            else m_funds_amount = ParseAmount(val.getValStr());
        }
    }
    {   const auto& val = contract[name_mining_fee_rate];
        if (!val.isNull()) {
            if (m_mining_fee_rate) {
                if (*m_mining_fee_rate != ParseAmount(val.getValStr())) throw ContractError(std::string(name_mining_fee_rate));
            }
            else m_mining_fee_rate = ParseAmount(val.getValStr());
        }
    }
    {   const auto& val = contract[name_funds_commit_sig];
        if (!val.isNull()) {
            if (m_funds_commit_sig) {
                if (*m_funds_commit_sig != unhex<signature>(val.get_str())) throw ContractError(std::string(name_funds_commit_sig));
            }
            else m_funds_commit_sig = unhex<signature>(val.get_str());
        }
    }
    {   const auto& val = contract[name_ord_swap_sig_A];
        if (!val.isNull()) {
            if (m_ord_swap_sig_A) {
                if (*m_ord_swap_sig_A != unhex<signature>(val.get_str())) throw ContractError(std::string(name_ord_swap_sig_A));
            }
            else m_ord_swap_sig_A = unhex<signature>(val.get_str());
        }
    }
    {   const auto& val = contract[name_ord_swap_sig_M];
        if (!val.isNull()) {
            if (m_ord_swap_sig_M) {
                if (*m_ord_swap_sig_M != unhex<signature>(val.get_str())) throw ContractError(std::string(name_ord_swap_sig_M));
            }
            else m_ord_swap_sig_M = unhex<signature>(val.get_str());
        }
    }
    {   const auto& val = contract[name_funds_swap_sig_B];
        if (!val.isNull()) {
            if (m_funds_swap_sig_B) {
                if (*m_funds_swap_sig_B != unhex<signature>(val.get_str())) throw ContractError(std::string(name_funds_swap_sig_B));
            }
            else m_funds_swap_sig_B = unhex<signature>(val.get_str());
        }
    }
    {   const auto& val = contract[name_funds_swap_sig_M];
        if (!val.isNull()) {
            if (m_funds_swap_sig_M) {
                if (*m_funds_swap_sig_M != unhex<signature>(val.get_str())) throw ContractError(std::string(name_funds_swap_sig_M));
            }
            else m_funds_swap_sig_M = unhex<signature>(val.get_str());
        }
    }
    {   const auto& val = contract[name_ordpayoff_sig];
        if (!val.isNull()) {
            if (m_ordpayoff_sig) {
                if (*m_ordpayoff_sig != unhex<signature>(val.get_str())) throw ContractError(std::string(name_ordpayoff_sig));
            }
            else m_ordpayoff_sig = unhex<signature>(val.get_str());
        }
    }
}

const CMutableTransaction &SwapInscriptionBuilder::GetOrdCommitTx()
{
    if (!mOrdCommitTx) {
        CheckContractTerms(OrdCommitSig);

        auto commit_pubkeyscript = CScript() << 1 << get<0>(OrdCommitTapRoot());

        CMutableTransaction commit_tx;
        commit_tx.vin = {CTxIn(COutPoint(uint256S(*m_ord_txid), *m_ord_nout))};
        commit_tx.vin.front().scriptWitness.stack.push_back(*m_ord_commit_sig);
        commit_tx.vout = {CTxOut(*m_ord_amount, commit_pubkeyscript)};
        commit_tx.vout.front().nValue = CalculateOutputAmount(*m_ord_amount, *m_ord_commit_mining_fee_rate, commit_tx);

        mOrdCommitTx = move(commit_tx);
    }
    return *mOrdCommitTx;
}


const CMutableTransaction &SwapInscriptionBuilder::GetFundsCommitTx()
{
    if (!mFundsCommitTx) {
        CheckContractTerms(FundsCommitSig);

        auto commit_pubkeyscript = CScript() << 1 << get<0>(FundsCommitTapRoot());

        CMutableTransaction commit_tx;
        commit_tx.vin = {CTxIn(COutPoint(uint256S(m_funds_txid.value()), m_funds_nout.value()))};
        commit_tx.vin.front().scriptWitness.stack.emplace_back(*m_funds_commit_sig);
        commit_tx.vout = {CTxOut(m_funds_amount.value(), commit_pubkeyscript)};
        commit_tx.vout.front().nValue = CalculateOutputAmount(*m_funds_amount, *m_mining_fee_rate, commit_tx);

        mFundsCommitTx = move(commit_tx);
    }
    return *mFundsCommitTx;
}

const CMutableTransaction &SwapInscriptionBuilder::GetSwapTx()
{
    if (!mSwapTx) {
        CheckContractTerms(MarketSwapSig);

        mSwapTx.emplace(MakeSwapTx(true));
    }
    return *mSwapTx;
}

const CMutableTransaction &SwapInscriptionBuilder::GetPayoffTx()
{
    if (!mOrdPayoffTx) {
        CheckContractTerms(MarketPayoffSig);

        CScript transfer_pubkeyscript = CScript() << 1 << *m_swap_script_pk_B;

        CMutableTransaction swap_tx(MakeSwapTx(true));

        CMutableTransaction transfer_tx;

        transfer_tx.vin = {CTxIn(swap_tx.GetHash(), 0)};
        transfer_tx.vin.front().scriptWitness.stack.push_back(*m_ordpayoff_sig);
        transfer_tx.vout = {CTxOut(swap_tx.vout[0].nValue, move(transfer_pubkeyscript))};
        transfer_tx.vout.front().nValue = CalculateOutputAmount(swap_tx.vout[0].nValue, *m_mining_fee_rate, transfer_tx);

        mOrdPayoffTx = move(transfer_tx);
    }
    return *mOrdPayoffTx;
}


}
