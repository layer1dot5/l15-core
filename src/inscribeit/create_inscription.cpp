
#include <ranges>

#include "univalue.h"

#include "serialize.h"
#include "interpreter.h"
#include "core_io.h"

#include "streams.h"
#include "create_inscription.hpp"
#include "utils.hpp"
#include "script_merkle_tree.hpp"
#include "channel_keys.hpp"


namespace l15::inscribeit {

namespace {

const std::string val_create_inscription("CreateInscription");


const size_t chunk_size = 520;
const bytevector ord_tag {'o', 'r', 'd'};
const bytevector one_tag {'\1'};


CScript MakeInscriptionScript(const xonly_pubkey& pk, const std::string& content_type, const bytevector& data) {
    CScript script;
    script << pk;
    script << OP_CHECKSIG;
    script << OP_0;
    script << OP_IF;
    script << ord_tag;
    script << one_tag;
    script << bytevector(content_type.begin(), content_type.end());
    script << OP_0;

    auto pos = data.begin();
    for ( ; pos + chunk_size < data.end(); pos += chunk_size) {
        script << bytevector(pos, pos + chunk_size);
    }
    if (pos != data.end()) {
        script << bytevector(pos, data.end());
    }
    script << OP_ENDIF;

    return script;
}


}

const uint32_t CreateInscriptionBuilder::m_protocol_version = 1;

const std::string CreateInscriptionBuilder::name_utxo_txid = "utxo_txid";
const std::string CreateInscriptionBuilder::name_utxo_nout = "utxo_nout";
const std::string CreateInscriptionBuilder::name_utxo_amount = "utxo_amount";
const std::string CreateInscriptionBuilder::name_utxo_pk = "utxo_pk";
const std::string CreateInscriptionBuilder::name_content_type = "content_type";
const std::string CreateInscriptionBuilder::name_content = "content";
const std::string CreateInscriptionBuilder::name_utxo_sig = "utxo_sig";
const std::string CreateInscriptionBuilder::name_inscribe_script_pk = "inscribe_script_pk";
const std::string CreateInscriptionBuilder::name_inscribe_int_pk = "inscribe_int_pk";
const std::string CreateInscriptionBuilder::name_inscribe_sig = "inscribe_sig";
const std::string CreateInscriptionBuilder::name_destination_pk = "destination_pk";


CreateInscriptionBuilder &l15::inscribeit::CreateInscriptionBuilder::UTXO(const string &txid, uint32_t nout, const std::string& amount)
{
    m_txid = txid;
    m_nout = nout;
    m_amount = ParseAmount(amount);
    return *this;
}

CreateInscriptionBuilder &CreateInscriptionBuilder::FeeRate(const string &rate)
{
    m_mining_fee_rate = ParseAmount(rate);
    return *this;
}

CreateInscriptionBuilder &CreateInscriptionBuilder::Data(const std::string& content_type, const string &hex_data)
{
    m_content_type = content_type;
    m_content = unhex<bytevector>(hex_data);
    return *this;
}

CreateInscriptionBuilder &CreateInscriptionBuilder::Destination(const string &pk)
{
    m_destination_pk = unhex<xonly_pubkey>(pk);
    return *this;
}


void CreateInscriptionBuilder::CheckBuildArgs() const
{
    if (!m_destination_pk) {
        throw std::invalid_argument("No destination public key is provided");
    }
    if (!m_content) {
        throw std::invalid_argument("No content data is provided");
    }
    if (!m_content_type) {
        throw std::invalid_argument("No content-type is provided");
    }
    if (!m_txid || !m_nout) {
        throw std::invalid_argument("No UTXO is provided");
    }
    if (!m_amount) {
        throw std::invalid_argument("No UTXO amount is provided");
    }
    if (!m_mining_fee_rate) {
        throw std::invalid_argument("No mining fee rate is provided");
    }

}

void CreateInscriptionBuilder::CheckRestoreArgs(const UniValue& contract) const
{
    if (!contract.exists(name_utxo_txid)) {
        throw std::invalid_argument("No UTXO txid is provided");
    }
    if (!contract.exists(name_utxo_nout)) {
        throw std::invalid_argument("No UTXO nout is provided");
    }
    if (!contract.exists(name_utxo_amount)) {
        throw std::invalid_argument("No UTXO amount is provided");
    }
    if (!contract.exists(name_utxo_pk)) {
        throw std::invalid_argument("No UTXO pubkey is provided");
    }
    if (!contract.exists(name_mining_fee_rate)) {
        throw std::invalid_argument("No transaction fee rate is provided");
    }
    if (!contract.exists(name_content_type)) {
        throw std::invalid_argument("No data content-type is provided");
    }
    if (!contract.exists(name_content)) {
        throw std::invalid_argument("No inscription media data is provided");
    }
    if (!contract.exists(name_utxo_sig)) {
        throw std::invalid_argument("No utxo signature is provided");
    }
    if (!contract.exists(name_inscribe_script_pk)) {
        throw std::invalid_argument("No inscription script pk is provided");
    }
    if (!contract.exists(name_inscribe_int_pk)) {
        throw std::invalid_argument("No insription transaction internal pk is provided");
    }
    if (!contract.exists(name_inscribe_sig)) {
        throw std::invalid_argument("No inscription genesis signature provided");
    }
    if (!contract.exists(name_destination_pk)) {
        throw std::invalid_argument("No destination pk is provided");
    }
}

void CreateInscriptionBuilder::Sign(std::string utxo_sk)
{
    CheckBuildArgs();

    core::ChannelKeys utxo_key(unhex<seckey>(utxo_sk));
    core::ChannelKeys inscribe_script_key;
    core::ChannelKeys inscribe_internal_key;

    CScript genesis_script = MakeInscriptionScript(inscribe_script_key.GetLocalPubKey(), *m_content_type, *m_content);
    ScriptMerkleTree genesis_tap_tree(TreeBalanceType::WEIGHTED, {genesis_script});
    uint256 root = genesis_tap_tree.CalculateRoot();
    m_insribe_script_pk = inscribe_script_key.GetLocalPubKey();

    auto taproot = inscribe_internal_key.NewKeyAddTapTweak(root);
    core::ChannelKeys inscrube_taproot_key(move(taproot.first));
    uint8_t inscribe_taproot_parity = taproot.second;
    m_inscribe_int_pk = inscribe_internal_key.GetLocalPubKey();

    CScript utxo_pubkeyscript;
    utxo_pubkeyscript << 1;
    utxo_pubkeyscript << utxo_key.GetLocalPubKey();
    m_utxo_pk = utxo_key.GetLocalPubKey();

    CScript funding_pubkeyscript;
    funding_pubkeyscript << 1;
    funding_pubkeyscript << inscrube_taproot_key.GetLocalPubKey();
    //m_inscribe_taproot_pk = inscrube_taproot_key.GetLocalPubKey();

    CScript genesis_pubkeyscript;
    genesis_pubkeyscript << 1;
    genesis_pubkeyscript << *m_destination_pk;

    CMutableTransaction funding_tx;
    funding_tx.vin = {CTxIn(COutPoint(uint256S(*m_txid), *m_nout))};
    funding_tx.vout = {CTxOut(*m_amount, funding_pubkeyscript)};
    funding_tx.vin.front().scriptWitness.stack.emplace_back(64); // Empty value is needed to obtain correct tx size

    funding_tx.vout.front().nValue = CalculateOutputAmount(*m_amount, *m_mining_fee_rate, funding_tx);

    m_utxo_sig = utxo_key.SignTaprootTx(
                funding_tx, 0,
                {CTxOut(*m_amount, utxo_pubkeyscript)}, {});

    funding_tx.vin.front().scriptWitness.stack.front() = static_cast<bytevector&>(*m_utxo_sig);


    CMutableTransaction genesis_tx;
    genesis_tx.vin = {CTxIn(COutPoint(funding_tx.GetHash(), 0))};
    genesis_tx.vout = {CTxOut(*m_amount, genesis_pubkeyscript)};

    genesis_tx.vin.front().scriptWitness.stack.emplace_back(64);  // Empty value is needed to obtain correct tx size
    genesis_tx.vin.front().scriptWitness.stack.emplace_back(genesis_script.begin(), genesis_script.end());

    auto genesis_scriptpath = genesis_tap_tree.CalculateScriptPath(genesis_script);

    bytevector control_block = {static_cast<uint8_t>(0xc0 | inscribe_taproot_parity)};
    control_block.reserve(1 + inscribe_internal_key.GetLocalPubKey().size() + genesis_scriptpath.size() * uint256::size());
    control_block.insert(control_block.end(), inscribe_internal_key.GetLocalPubKey().begin(), inscribe_internal_key.GetLocalPubKey().end());

    for(uint256 &branch_hash : genesis_scriptpath)
        control_block.insert(control_block.end(), branch_hash.begin(), branch_hash.end());

    genesis_tx.vin.front().scriptWitness.stack.emplace_back(control_block);
    genesis_tx.vout.front().nValue = CalculateOutputAmount(funding_tx.vout.front().nValue, *m_mining_fee_rate, genesis_tx);

    m_inscribe_script_sig = inscribe_script_key.SignTaprootTx(
            genesis_tx, 0,
            {funding_tx.vout.front()}, genesis_script);

    genesis_tx.vin.front().scriptWitness.stack.front() = static_cast<bytevector&>(*m_inscribe_script_sig);

    m_inscribe_taproot_sk = inscrube_taproot_key.GetLocalPrivKey();

    mFundingTx.emplace(move(funding_tx));
    mGenesisTx.emplace(move(genesis_tx));

}

std::vector<std::string> CreateInscriptionBuilder::RawTransactions() const
{
    if (!mFundingTx || !mGenesisTx) {
        throw std::logic_error("Transaction data unavailable");
    }

    std::string funding_tx_hex = EncodeHexTx(CTransaction(*mFundingTx));
    std::string genesis_tx_hex = EncodeHexTx(CTransaction(*mGenesisTx));
    return {move(funding_tx_hex), move(genesis_tx_hex)};
}

std::string CreateInscriptionBuilder::Serialize() const
{
    UniValue contract(UniValue::VOBJ);
    contract.pushKV(name_version, (int)m_protocol_version);
    contract.pushKV(name_utxo_txid, m_txid.value());
    contract.pushKV(name_utxo_nout, (int)m_nout.value());
    contract.pushKV(name_utxo_amount, m_amount.value());
    contract.pushKV(name_utxo_pk, hex(m_utxo_pk.value()));
    contract.pushKV(name_mining_fee_rate, m_mining_fee_rate.value());
    contract.pushKV(name_content_type, m_content_type.value());
    contract.pushKV(name_content, hex(m_content.value()));
    contract.pushKV(name_utxo_sig, hex(m_utxo_sig.value()));

    contract.pushKV(name_inscribe_script_pk, hex(m_insribe_script_pk.value()));
    contract.pushKV(name_inscribe_int_pk, hex(m_inscribe_int_pk.value()));
    contract.pushKV(name_inscribe_sig, hex(m_inscribe_script_sig.value()));

    contract.pushKV(name_destination_pk, hex(m_destination_pk.value()));

    UniValue dataRoot(UniValue::VOBJ);
    dataRoot.pushKV(name_contract_type, val_create_inscription);
    dataRoot.pushKV(name_params, contract);

    return dataRoot.write();
}

void CreateInscriptionBuilder::Deserialize(const string &data)
{
    UniValue dataRoot;
    dataRoot.read(data);

    if (dataRoot[name_contract_type].get_str() != val_create_inscription) {
        throw ContractProtocolError("SwapInscription contract does not match " + dataRoot[name_contract_type].getValStr());
    }

    UniValue contract = dataRoot[name_params];

    if (contract[name_version].getInt<uint32_t>() != m_protocol_version) {
        throw ContractProtocolError("Wrong SwapInscription contract version: " + contract[name_version].getValStr());
    }

    CheckRestoreArgs(contract);

    m_txid = contract[name_utxo_txid].get_str();
    m_nout = contract[name_utxo_nout].getInt<uint32_t>();
    m_amount = contract[name_utxo_amount].getInt<int64_t>();

    m_utxo_pk = unhex<xonly_pubkey>(contract[name_utxo_pk].get_str());
    m_mining_fee_rate = contract[name_mining_fee_rate].getInt<int64_t>();
    m_content_type = contract[name_content_type].get_str();
    m_content = unhex<bytevector>(contract[name_content].get_str());
    m_utxo_sig = unhex<signature>(contract[name_utxo_sig].get_str());

    m_insribe_script_pk = unhex<xonly_pubkey>(contract[name_inscribe_script_pk].get_str());
    m_inscribe_int_pk = unhex<xonly_pubkey>(contract[name_inscribe_int_pk].get_str());
    m_inscribe_script_sig = unhex<signature>(contract[name_inscribe_sig].get_str());

    m_destination_pk = unhex<xonly_pubkey>(contract[name_destination_pk].get_str());

    RestoreTransactions();
}

void CreateInscriptionBuilder::RestoreTransactions()
{
    CScript genesis_script = MakeInscriptionScript(m_insribe_script_pk.value(), *m_content_type, *m_content);
    ScriptMerkleTree genesis_tap_tree(TreeBalanceType::WEIGHTED, {genesis_script});
    uint256 root = genesis_tap_tree.CalculateRoot();

    auto inscribe_taproot = core::ChannelKeys::AddTapTweak(m_inscribe_int_pk.value(), root);
    xonly_pubkey inscribe_taproot_pk = inscribe_taproot.first;
    uint8_t inscribe_taproot_parity = inscribe_taproot.second;

    CScript utxo_pubkeyscript;
    utxo_pubkeyscript << 1;
    utxo_pubkeyscript << m_utxo_pk.value();

    CScript funding_pubkeyscript;
    funding_pubkeyscript << 1;
    funding_pubkeyscript << inscribe_taproot_pk;

    CScript genesis_pubkeyscript;
    genesis_pubkeyscript << 1;
    genesis_pubkeyscript << m_destination_pk.value();

    CMutableTransaction funding_tx;
    funding_tx.vin = {CTxIn(COutPoint(uint256S(*m_txid), *m_nout))};
    funding_tx.vin.front().scriptWitness.stack.push_back(m_utxo_sig.value());
    funding_tx.vout = {CTxOut(*m_amount, funding_pubkeyscript)};
    funding_tx.vout.front().nValue = CalculateOutputAmount(*m_amount, *m_mining_fee_rate, funding_tx);

    CMutableTransaction genesis_tx;
    genesis_tx.vin = {CTxIn(COutPoint(funding_tx.GetHash(), 0))};
    genesis_tx.vout = {CTxOut(*m_amount, genesis_pubkeyscript)};

    genesis_tx.vin.front().scriptWitness.stack.push_back(m_inscribe_script_sig.value());
    genesis_tx.vin.front().scriptWitness.stack.emplace_back(genesis_script.begin(), genesis_script.end());

    auto genesis_scriptpath = genesis_tap_tree.CalculateScriptPath(genesis_script);

    bytevector control_block = {static_cast<uint8_t>(0xc0 | inscribe_taproot_parity)};
    control_block.reserve(1 + m_inscribe_int_pk->size() + genesis_scriptpath.size() * uint256::size());
    control_block.insert(control_block.end(), m_inscribe_int_pk->begin(), m_inscribe_int_pk->end());

    for(uint256 &branch_hash : genesis_scriptpath)
        control_block.insert(control_block.end(), branch_hash.begin(), branch_hash.end());

    genesis_tx.vin.front().scriptWitness.stack.emplace_back(control_block);
    genesis_tx.vout.front().nValue = CalculateOutputAmount(funding_tx.vout.front().nValue, *m_mining_fee_rate, genesis_tx);

    mFundingTx.emplace(move(funding_tx));
    mGenesisTx.emplace(move(genesis_tx));
}

}
