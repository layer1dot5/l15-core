
#include <ranges>
#include <exception>

#include "univalue.h"

#include "serialize.h"
#include "interpreter.h"
#include "core_io.h"

#include "streams.h"
#include "create_inscription.hpp"
#include "script_merkle_tree.hpp"
#include "channel_keys.hpp"

namespace l15::inscribeit {

namespace {

const std::string val_create_inscription("CreateInscription");

const size_t chunk_size = 520;
const bytevector ORD_TAG {'o', 'r', 'd'};
const opcodetype CONTENT_TAG {OP_0};
const bytevector CONTENT_TYPE_TAG {'\1'};
const bytevector COLLECTION_ID_TAG {'\2'};

CScript MakeInscriptionScript(const xonly_pubkey& pk, const std::string& content_type, const bytevector& data, const std::optional<std::string>& inscription_id = {})
{
    CScript script;
    script << pk;
    script << OP_CHECKSIG;
    script << OP_0;
    script << OP_IF;
    script << ORD_TAG;
    script << CONTENT_TYPE_TAG;
    script << bytevector(content_type.begin(), content_type.end());

    if (inscription_id) {
        script << COLLECTION_ID_TAG;
        script << bytevector(inscription_id->begin(), inscription_id->end());
    }

    script << CONTENT_TAG;
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

void CheckCollectionId(const std::string& collection_id)
{
    if (collection_id[64] != 'i') throw ContractTermWrongValue("collection id: " + collection_id);
    try {
        unhex<bytevector>(collection_id.substr(0, 64));
        std::stoul(collection_id.substr(65));
    }
    catch (const std::exception& e) {
        std::throw_with_nested(ContractTermWrongValue("collection id: " + collection_id));
    }
}

}

const uint32_t CreateInscriptionBuilder::m_protocol_version = 2;

const std::string CreateInscriptionBuilder::name_ord_amount = "ord_amount";
const std::string CreateInscriptionBuilder::name_utxo = "utxo";
const std::string CreateInscriptionBuilder::name_utxo_txid = "txid";
const std::string CreateInscriptionBuilder::name_utxo_nout = "nout";
const std::string CreateInscriptionBuilder::name_utxo_amount = "amount";
const std::string CreateInscriptionBuilder::name_utxo_pk = "pubkey";
const std::string CreateInscriptionBuilder::name_utxo_sig = "sig";
const std::string CreateInscriptionBuilder::name_collection = "collection";
const std::string CreateInscriptionBuilder::name_collection_id = "collection_id";
const std::string CreateInscriptionBuilder::name_content_type = "content_type";
const std::string CreateInscriptionBuilder::name_content = "content";
const std::string CreateInscriptionBuilder::name_inscribe_script_pk = "inscribe_script_pk";
const std::string CreateInscriptionBuilder::name_inscribe_int_pk = "inscribe_int_pk";
const std::string CreateInscriptionBuilder::name_inscribe_sig = "inscribe_sig";
const std::string CreateInscriptionBuilder::name_destination_pk = "destination_pk";


CreateInscriptionBuilder &CreateInscriptionBuilder::AddUTXO(const string &txid, uint32_t nout, const std::string& amount, const std::string& pk)
{
    m_utxo.emplace_back(std::string(txid), nout, ParseAmount(amount), unhex<xonly_pubkey>(pk));
    return *this;
}

CreateInscriptionBuilder& CreateInscriptionBuilder::AddToCollection(const std::string& collection_id,
                                                                    const string& utxo_txid, uint32_t utxo_nout,
                                                                    const std::string& utxo_amount)
{
    CheckCollectionId(collection_id);
    m_collection_id = collection_id;
    m_collection_utxo = {utxo_txid, utxo_nout, ParseAmount(utxo_amount)};
    return *this;
}

CreateInscriptionBuilder &CreateInscriptionBuilder::MiningFeeRate(const string &rate)
{
    SetMiningFeeRate(rate);
    return *this;
}

CreateInscriptionBuilder &CreateInscriptionBuilder::Data(const std::string& content_type, const string &hex_data)
{
    m_content_type = content_type;
    m_content = unhex<bytevector>(hex_data);
    return *this;
}

CreateInscriptionBuilder &CreateInscriptionBuilder::DestinationPubKey(const string &pk)
{
    m_destination_pk = unhex<xonly_pubkey>(pk);
    return *this;
}

std::string CreateInscriptionBuilder::GetInscribeInternaltPubKey() const
{
    if (m_inscribe_int_pk) {
        return hex(*m_inscribe_int_pk);
    }
    else
        throw ContractStateError(std::string(name_inscribe_int_pk) + " undefined");
}

void CreateInscriptionBuilder::CheckBuildArgs() const
{
    if (!m_destination_pk) {
        throw ContractTermMissing("destination pubkey");
    }
    if (!m_content) {
        throw ContractTermMissing("content");
    }
    if (!m_content_type) {
        throw ContractTermMissing("content-type");
    }
    if (m_utxo.empty()) {
        throw ContractTermMissing("UTXO");
    }
    if (!m_mining_fee_rate) {
        throw ContractTermMissing("mining fee rate");
    }
    CheckAmount();
}

void CreateInscriptionBuilder::CheckAmount() const
{
    CAmount utxo_amount = 0;
    for (const auto& utxo: m_utxo) {
        utxo_amount += utxo.m_amount;
    }
    if (utxo_amount < m_ord_amount + CalculateWholeFee()) {
        throw ContractTermWrongValue("UTXO amount is not enough");
    }
    if (m_collection_utxo && m_collection_utxo->m_amount <= Dust(*m_mining_fee_rate)) {
        throw ContractTermWrongValue("collection UTXO amount is not enough");
    }
}


void CreateInscriptionBuilder::SignCommit(uint32_t n, const std::string& sk, const std::string& inscribe_script_pk)
{
    if (n >= m_utxo.size()) throw ContractTermMissing(name_utxo + '[' + std::to_string(n) + ']');
    CheckBuildArgs();

    auto utxo_it = m_utxo.begin();
    std::advance(utxo_it, n);
    core::ChannelKeys utxo_key(unhex<seckey>(sk));
    if (utxo_key.GetLocalPubKey() != utxo_it->m_pubkey) throw ContractValueMismatch(name_utxo + '[' + std::to_string(n) + ']' + name_utxo_pk);

    if (!m_inscribe_int_pk) {
        core::ChannelKeys inscribe_internal_key = core::ChannelKeys();
        m_inscribe_int_sk = inscribe_internal_key.GetLocalPrivKey();
        m_inscribe_int_pk = inscribe_internal_key.GetLocalPubKey();
    }

    if (m_inscribe_script_pk) {
        if (*m_inscribe_script_pk != unhex<xonly_pubkey>(inscribe_script_pk)) throw ContractValueMismatch(std::string(name_inscribe_script_pk));
    }
    else {
        m_inscribe_script_pk = unhex<xonly_pubkey>(inscribe_script_pk);
    }

    CAmount utxo_amount = 0;
    std::vector<CTxOut> spending_outs;
    spending_outs.reserve(m_utxo.size());
    for (const auto& utxo: m_utxo) {
        utxo_amount += utxo.m_amount;
        spending_outs.emplace_back(utxo.m_amount, CScript() << 1 << *utxo.m_pubkey);
    }

    CMutableTransaction funding_tx = CreateCommitTxTemplate();
    funding_tx.vout.front().nValue = CalculateOutputAmount(utxo_amount, *m_mining_fee_rate, funding_tx);

    utxo_it->m_sig = utxo_key.SignTaprootTx(funding_tx, n, move(spending_outs), {});
}

void CreateInscriptionBuilder::SignCollection(const std::string& sk)
{
    CheckBuildArgs();

    if (!m_inscribe_script_pk) throw ContractStateError(std::string(name_inscribe_script_pk) + " undefined");
    if (!m_inscribe_int_sk) throw ContractStateError(std::string("internal inscription key undefined: has commit tx been signed?"));

    core::ChannelKeys collection_key(unhex<seckey>(sk));
    m_collection_utxo->m_pubkey = collection_key.GetLocalPubKey();

    if (!m_inscribe_taproot_sk) {
        CScript genesis_script = MakeInscriptionScript(*m_inscribe_script_pk, *m_content_type, *m_content, m_collection_id);
        ScriptMerkleTree genesis_tap_tree(TreeBalanceType::WEIGHTED, {genesis_script});
        uint256 root = genesis_tap_tree.CalculateRoot();

        core::ChannelKeys inscribe_internal_key(*m_inscribe_int_sk);
        auto taproot = inscribe_internal_key.NewKeyAddTapTweak(root);
        m_inscribe_taproot_sk = taproot.first.GetLocalPrivKey();
    }

    const CMutableTransaction& commit_tx = CommitTx();

    CMutableTransaction genesis_tx = CreateGenesisTxTemplate();
    genesis_tx.vin[0].prevout.hash = commit_tx.GetHash();

    genesis_tx.vout.front().nValue = CalculateOutputAmount(commit_tx.vout.front().nValue, *m_mining_fee_rate, genesis_tx);

    std::vector<CTxOut> spending_outs = {commit_tx.vout.front(), {m_collection_utxo->m_amount, CScript() << 1 << *m_collection_utxo->m_pubkey}};

    m_collection_utxo->m_sig = collection_key.SignTaprootTx(genesis_tx, 1, move(spending_outs), {});
}

void CreateInscriptionBuilder::SignInscription(const std::string& insribe_script_sk)
{
    core::ChannelKeys script_keypair(unhex<seckey>(insribe_script_sk));
    if (!m_inscribe_script_pk) throw ContractStateError(std::string(name_inscribe_script_pk) + " undefined");
    if (*m_inscribe_script_pk != script_keypair.GetLocalPubKey()) throw ContractValueMismatch(std::string(name_inscribe_script_pk));
    if (!m_inscribe_int_sk) throw ContractStateError(std::string("internal inscription key undefined: has commit tx been signed?"));
    if (m_collection_utxo && !m_collection_utxo->m_pubkey) throw ContractStateError("Need signed collection input before inscription");

    CScript genesis_script = MakeInscriptionScript(*m_inscribe_script_pk, *m_content_type, *m_content, m_collection_id);
    if (!m_inscribe_taproot_sk) {
        ScriptMerkleTree genesis_tap_tree(TreeBalanceType::WEIGHTED, {genesis_script});
        uint256 root = genesis_tap_tree.CalculateRoot();

        core::ChannelKeys inscribe_internal_key(*m_inscribe_int_sk);
        auto taproot = inscribe_internal_key.NewKeyAddTapTweak(root);
        m_inscribe_taproot_sk = taproot.first.GetLocalPrivKey();
    }

    const CMutableTransaction& commit_tx = CommitTx();
    CMutableTransaction genesis_tx = CreateGenesisTxTemplate();
    genesis_tx.vin[0].prevout.hash = commit_tx.GetHash();

    genesis_tx.vout.front().nValue = CalculateOutputAmount(commit_tx.vout.front().nValue, *m_mining_fee_rate, genesis_tx);

    std::vector<CTxOut> spending_outs = {commit_tx.vout.front()};
    if (m_collection_utxo) {
        spending_outs.emplace_back(m_collection_utxo->m_amount, CScript() << 1 << *m_collection_utxo->m_pubkey);
    }

    m_inscribe_script_sig = script_keypair.SignTaprootTx(genesis_tx, 0, move(spending_outs), genesis_script);
}

std::vector<std::string> CreateInscriptionBuilder::RawTransactions() const
{
    if (!mCommitTx || !mGenesisTx) {
        throw ContractStateError("Transaction data unavailable");
    }

    std::string funding_tx_hex = EncodeHexTx(CTransaction(*mCommitTx));
    std::string genesis_tx_hex = EncodeHexTx(CTransaction(*mGenesisTx));
    return {move(funding_tx_hex), move(genesis_tx_hex)};
}

std::string CreateInscriptionBuilder::Serialize() const
{
    UniValue contract(UniValue::VOBJ);
    contract.pushKV(name_version, (int)m_protocol_version);
    contract.pushKV(name_ord_amount, m_ord_amount);
    contract.pushKV(name_mining_fee_rate, *m_mining_fee_rate);

    UniValue utxo_arr(UniValue::VARR);
    for (const auto& utxo: m_utxo) {
        UniValue utxo_val(UniValue::VOBJ);
        utxo_val.pushKV(name_utxo_txid, utxo.m_txid);
        utxo_val.pushKV(name_utxo_nout, utxo.m_nout);
        utxo_val.pushKV(name_utxo_amount, utxo.m_amount);
        utxo_val.pushKV(name_utxo_sig, hex(*utxo.m_sig));

        utxo_arr.push_back(move(utxo_val));
    }
    contract.pushKV(name_utxo, utxo_arr);

    if (m_collection_utxo) {
        UniValue collection_val(UniValue::VOBJ);
        collection_val.pushKV(name_utxo_txid, m_collection_utxo->m_txid);
        collection_val.pushKV(name_utxo_nout, m_collection_utxo->m_nout);
        collection_val.pushKV(name_utxo_amount, m_collection_utxo->m_amount);
        collection_val.pushKV(name_utxo_pk, hex(*m_collection_utxo->m_pubkey));
        collection_val.pushKV(name_utxo_sig, hex(*m_collection_utxo->m_sig));
        collection_val.pushKV(name_collection_id, *m_collection_id);
        contract.pushKV(name_collection, move(collection_val));
    }

    contract.pushKV(name_content_type, m_content_type.value());
    contract.pushKV(name_content, hex(m_content.value()));

    contract.pushKV(name_inscribe_script_pk, hex(m_inscribe_script_pk.value()));
    contract.pushKV(name_inscribe_int_pk, GetInscribeInternaltPubKey());
    contract.pushKV(name_inscribe_sig, hex(m_inscribe_script_sig.value()));

    contract.pushKV(name_destination_pk, hex(m_destination_pk.value()));

    UniValue dataRoot(UniValue::VOBJ);
    dataRoot.pushKV(name_contract_type, val_create_inscription);
    dataRoot.pushKV(name_params, move(contract));

    return dataRoot.write();
}

void CreateInscriptionBuilder::Deserialize(const string &data)
{
    UniValue root;
    root.read(data);

    if (root[name_contract_type].get_str() != val_create_inscription) {
        throw ContractProtocolError("CreateInscription contract does not match " + root[name_contract_type].getValStr());
    }

    const UniValue& contract = root[name_params];

    if (contract[name_version].getInt<uint32_t>() != m_protocol_version) {
        throw ContractProtocolError("Wrong CreateInscription contract version: " + contract[name_version].getValStr());
    }

    {   const auto &val = contract[name_ord_amount];
        if (val.isNull()) throw ContractTermMissing(std::string(name_ord_amount));
        if (!val.isNum() || val.getInt<CAmount>() != m_ord_amount)
            throw ContractTermWrongValue(std::string(name_ord_amount) + ": " + contract[name_ord_amount].getValStr() + ", awaited: " + std::to_string(m_ord_amount));
    }

    {   const auto &val = contract[name_utxo];

        if (val.isNull()) throw ContractTermMissing(std::string(name_utxo));
        if (!val.isArray()) throw ContractTermWrongFormat(std::string(name_utxo));
        if (val.empty()) throw ContractTermMissing(std::string(name_utxo));

        for (size_t n = 0; n < val.size(); ++n) {
            const UniValue &utxo = val[n];

            if (!utxo.exists(name_utxo_txid))
                throw ContractTermMissing(std::string(name_utxo) + '[' + std::to_string(n) + "]." + name_utxo_txid);
            if (!utxo.exists(name_utxo_nout))
                throw ContractTermMissing(std::string(name_utxo) + '[' + std::to_string(n) + "]." + name_utxo_nout);
            if (!utxo.exists(name_utxo_amount))
                throw ContractTermMissing(std::string(name_utxo) + '[' + std::to_string(n) + "]." + name_utxo_amount);
            if (!utxo.exists(name_utxo_sig))
                throw ContractTermMissing(std::string(name_utxo) + '[' + std::to_string(n) + "]." + name_utxo_sig);

            std::string txid = utxo[name_utxo_txid].get_str();
            uint32_t nout = utxo[name_utxo_nout].getInt<uint32_t>();
            CAmount amount = utxo[name_utxo_amount].getInt<CAmount>();
            signature sig = unhex<signature>(utxo[name_utxo_sig].get_str());

            m_utxo.emplace_back(move(txid), nout, amount);
            m_utxo.back().m_sig = move(sig);
        }
    }
    {   const auto &val = contract[name_collection];
        if (!val.isNull()) {
            if (!val.isObject()) throw ContractTermWrongFormat(std::string(name_collection));

            if (!val.exists(name_utxo_txid))
                throw ContractTermMissing(std::string(name_collection) + "." + name_utxo_txid);
            if (!val.exists(name_utxo_nout))
                throw ContractTermMissing(std::string(name_collection) + "." + name_utxo_nout);
            if (!val.exists(name_utxo_amount))
                throw ContractTermMissing(std::string(name_collection) + "." + name_utxo_amount);
            if (!val.exists(name_utxo_pk))
                throw ContractTermMissing(std::string(name_collection) + "." + name_utxo_pk);
            if (!val.exists(name_utxo_sig))
                throw ContractTermMissing(std::string(name_collection) + "." + name_utxo_sig);
            if (!val.exists(name_collection_id))
                throw ContractTermMissing(std::string(name_collection) + "." + name_collection_id);

            m_collection_id = val[name_collection_id].get_str();

            std::string txid = val[name_utxo_txid].get_str();
            uint32_t nout = val[name_utxo_nout].getInt<uint32_t>();
            CAmount amount = val[name_utxo_amount].getInt<CAmount>();
            xonly_pubkey pk = unhex<signature>(val[name_utxo_pk].get_str());
            signature sig = unhex<signature>(val[name_utxo_sig].get_str());

            m_collection_utxo = {move(txid), nout, amount, move(pk), move(sig)};
        }
    }
    {   const auto &val = contract[name_mining_fee_rate];
        if (val.isNull()) throw ContractTermMissing(std::string(name_mining_fee_rate));
        m_mining_fee_rate = val.getInt<int64_t>();
    }
    {   const auto &val = contract[name_content_type];
        if (val.isNull()) throw ContractTermMissing(std::string(name_content_type));
        m_content_type = val.get_str();
    }
    {   const auto &val = contract[name_content];
        if (val.isNull()) throw ContractTermMissing(std::string(name_content));
        m_content = unhex<bytevector>(val.get_str());
    }
    {   const auto &val = contract[name_inscribe_script_pk];
        if (val.isNull()) throw ContractTermMissing(std::string(name_inscribe_script_pk));
        m_inscribe_script_pk = unhex<xonly_pubkey>(val.get_str());
    }
    {   const auto &val = contract[name_inscribe_sig];
        if (val.isNull()) throw ContractTermMissing(std::string(name_inscribe_sig));
        m_inscribe_script_sig = unhex<signature>(val.get_str());
    }
    {   const auto &val = contract[name_inscribe_int_pk];
        if (val.isNull()) throw ContractTermMissing(std::string(name_inscribe_int_pk));
        m_inscribe_int_pk = unhex<xonly_pubkey>(val.get_str());
    }
    {   const auto &val = contract[name_destination_pk];
        if (val.isNull()) throw ContractTermMissing(std::string(name_destination_pk));
        m_destination_pk = unhex<xonly_pubkey>(val.get_str());
    }
    CheckAmount();

    RestoreTransactions();
}

const CMutableTransaction& CreateInscriptionBuilder::CommitTx() const
{
    if (!mCommitTx) {
        if (m_utxo.empty()) throw ContractTermMissing(std::string(name_utxo));
        uint32_t n = 0;
        CAmount utxo_amount = 0;
        for (const auto& utxo: m_utxo) {
            if (!utxo.m_sig) throw ContractTermMissing(std::string(name_utxo) + '[' + std::to_string(n) + "]." + name_utxo_sig);
            utxo_amount += utxo.m_amount;
            ++n;
        }

        CMutableTransaction tx = CreateCommitTxTemplate();
        tx.vout.front().nValue = CalculateOutputAmount(utxo_amount, *m_mining_fee_rate, tx);
        mCommitTx = move(tx);
    }
    return *mCommitTx;
}


void CreateInscriptionBuilder::RestoreTransactions()
{
    if (!m_inscribe_script_pk) throw ContractTermMissing(std::string(name_inscribe_script_pk));
    if (!m_inscribe_int_pk) throw ContractTermMissing(std::string(name_inscribe_int_pk));
    if (!m_inscribe_script_sig) throw ContractTermMissing(std::string(name_inscribe_sig));

    if (!m_collection_id && m_collection_utxo) throw ContractTermMissing(std::string(name_collection_id));
    if (!m_collection_utxo && m_collection_id) throw ContractTermMissing(std::string(name_collection));
    if (m_collection_utxo) {
        if (!m_collection_utxo->m_pubkey) throw ContractTermMissing(std::string(name_collection) + '.' + name_utxo_pk);
        if (!m_collection_utxo->m_sig) throw ContractTermMissing(std::string(name_collection) + '.' + name_utxo_sig);
    }

    const CMutableTransaction& commit_tx = CommitTx();
    CMutableTransaction genesis_tx = CreateGenesisTxTemplate();
    genesis_tx.vin[0].prevout.hash = commit_tx.GetHash();
    genesis_tx.vin[0].scriptWitness.stack[0] = *m_inscribe_script_sig;
    genesis_tx.vout[0].nValue = CalculateOutputAmount(commit_tx.vout.front().nValue, *m_mining_fee_rate, genesis_tx);

    mGenesisTx.emplace(move(genesis_tx));
}

CMutableTransaction CreateInscriptionBuilder::CreateCommitTxTemplate() const {

    CMutableTransaction result;

    if (!m_utxo.empty()) {
        result.vin.reserve(m_utxo.size());
        for (const auto &utxo: m_utxo) {
            result.vin.emplace_back(uint256S(utxo.m_txid), utxo.m_nout);
            result.vin.back().scriptWitness.stack.emplace_back(utxo.m_sig.value_or(signature()));
        }
    }
    else {
        result.vin.emplace_back(uint256(), 0);
        result.vin.back().scriptWitness.stack.emplace_back(64);
    }

    CScript pubkey_script;
    pubkey_script << 1;
    if (m_inscribe_taproot_sk) {
        core::ChannelKeys taproot_keypair(*m_inscribe_taproot_sk);
        pubkey_script << taproot_keypair.GetLocalPubKey();
    }
    else if (m_inscribe_int_pk && m_inscribe_script_pk) {
        CScript genesis_script = MakeInscriptionScript(*m_inscribe_script_pk, *m_content_type, *m_content, m_collection_id);
        ScriptMerkleTree genesis_tap_tree(TreeBalanceType::WEIGHTED, {genesis_script});
        uint256 root = genesis_tap_tree.CalculateRoot();
        auto taproot = core::ChannelKeys::AddTapTweak(*m_inscribe_int_pk, root);
        pubkey_script << get<0>(taproot);
    }
    else {
        pubkey_script << xonly_pubkey();
    }

    result.vout.emplace_back(0, pubkey_script);

    return result;
}

CMutableTransaction CreateInscriptionBuilder::CreateGenesisTxTemplate() const {
    if (!m_content_type) throw ContractStateError(std::string(name_content_type) + " undefined");
    if (!m_content) throw ContractStateError(std::string(name_content) + " undefined");

    auto emptyKey = xonly_pubkey();

    CScript genesis_script = MakeInscriptionScript(m_inscribe_script_pk ? *m_inscribe_script_pk : emptyKey, *m_content_type, *m_content, m_collection_id);
    ScriptMerkleTree genesis_tap_tree(TreeBalanceType::WEIGHTED, {genesis_script});
    uint256 root = genesis_tap_tree.CalculateRoot();

    uint8_t taproot_parity = 0;
    if (m_inscribe_int_pk) {
        auto taproot = core::ChannelKeys::AddTapTweak(*m_inscribe_int_pk, root);
        taproot_parity = taproot.second;
    }

    std::vector<uint256> genesis_scriptpath = genesis_tap_tree.CalculateScriptPath(genesis_script);
    bytevector control_block = {static_cast<uint8_t>(0xc0 | taproot_parity)};
    control_block.reserve(1 + emptyKey.size() + genesis_scriptpath.size() * uint256::size());
    if (m_inscribe_int_pk) {
        control_block.insert(control_block.end(), m_inscribe_int_pk->begin(), m_inscribe_int_pk->end());
    }
    else {
        control_block.insert(control_block.end(), emptyKey.begin(), emptyKey.end());
    }

    for(uint256 &branch_hash : genesis_scriptpath)
        control_block.insert(control_block.end(), branch_hash.begin(), branch_hash.end());

    CMutableTransaction result;

    result.vin = {{uint256(0), 0}};
    result.vin.front().scriptWitness.stack.emplace_back(m_inscribe_script_sig.value_or(signature()));
        result.vin.front().scriptWitness.stack.emplace_back(genesis_script.begin(), genesis_script.end());
    result.vin.front().scriptWitness.stack.emplace_back(control_block);

    result.vout = {CTxOut(0, CScript() << 1 << m_destination_pk.value_or(emptyKey))};

    if (m_collection_utxo) {
        result.vin.emplace_back(uint256S(m_collection_utxo->m_txid), m_collection_utxo->m_nout);
        result.vin.back().scriptWitness.stack.emplace_back(m_collection_utxo->m_sig.value_or(signature()));
        result.vout.emplace_back(m_collection_utxo->m_amount, CScript() << 1 << m_collection_utxo->m_pubkey.value_or(xonly_pubkey()));
    }

    return result;
}

std::vector<std::pair<CAmount,CMutableTransaction>> CreateInscriptionBuilder::GetTransactions() const {
    return {
        { *m_mining_fee_rate, CreateCommitTxTemplate() },
        { *m_mining_fee_rate, CreateGenesisTxTemplate()}
    };
}

std::string CreateInscriptionBuilder::GetMinFundingAmount() const {
    if(!m_content_type) {
        throw l15::TransactionError("content type is empty");
    }
    if(!m_content) {
        throw l15::TransactionError("content is empty");
    }
    return FormatAmount(m_ord_amount + CalculateWholeFee());
}

}
