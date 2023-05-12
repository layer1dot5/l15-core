
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

#include "inscription_common.hpp"

namespace l15::inscribeit {

namespace {

const std::string val_create_inscription("CreateInscription");


CScript MakeInscriptionScript(const xonly_pubkey& pk, const std::string& content_type, const bytevector& data, const std::optional<std::string>& collection_id = {})
{
    CScript script;
    script << pk;
    script << OP_CHECKSIG;
    script << OP_0;
    script << OP_IF;
    script << ORD_TAG;
    script << CONTENT_TYPE_TAG;
    script << bytevector(content_type.begin(), content_type.end());

    script << CONTENT_TAG;
    auto pos = data.begin();
    for ( ; pos + chunk_size < data.end(); pos += chunk_size) {
        script << bytevector(pos, pos + chunk_size);
    }
    if (pos != data.end()) {
        script << bytevector(pos, data.end());
    }

    if (collection_id) {
        script << COLLECTION_ID_TAG;
        script << bytevector(collection_id->begin(), collection_id->end());
    }

    script << OP_ENDIF;

    return script;
}

}

const uint32_t CreateInscriptionBuilder::m_protocol_version = 3;

const std::string CreateInscriptionBuilder::name_ord_amount = "ord_amount";
const std::string CreateInscriptionBuilder::name_utxo = "utxo";
const std::string CreateInscriptionBuilder::name_xtra_utxo = "xtra_utxo";
const std::string CreateInscriptionBuilder::name_txid = "txid";
const std::string CreateInscriptionBuilder::name_nout = "nout";
const std::string CreateInscriptionBuilder::name_amount = "amount";
const std::string CreateInscriptionBuilder::name_pk = "pubkey";
const std::string CreateInscriptionBuilder::name_sig = "sig";
const std::string CreateInscriptionBuilder::name_collection = "collection";
const std::string CreateInscriptionBuilder::name_collection_id = "collection_id";
const std::string CreateInscriptionBuilder::name_content_type = "content_type";
const std::string CreateInscriptionBuilder::name_content = "content";
const std::string CreateInscriptionBuilder::name_inscribe_script_pk = "inscribe_script_pk";
const std::string CreateInscriptionBuilder::name_inscribe_int_pk = "inscribe_int_pk";
const std::string CreateInscriptionBuilder::name_inscribe_sig = "inscribe_sig";
const std::string CreateInscriptionBuilder::name_destination_pk = "destination_pk";


CreateInscriptionBuilder &CreateInscriptionBuilder::AddUTXO(const std::string &txid, uint32_t nout,
                                                            const std::string& amount,
                                                            const std::string& pk)
{
    m_utxo.emplace_back(std::string(txid), nout, ParseAmount(amount), unhex<xonly_pubkey>(pk));
    return *this;
}

CreateInscriptionBuilder& CreateInscriptionBuilder::AddToCollection(const std::string& collection_id,
                                                                    const std::string& utxo_txid, uint32_t utxo_nout,
                                                                    const std::string& utxo_amount)
{
    CheckCollectionId(collection_id);
    m_collection_id = collection_id;
    m_collection_utxo = {utxo_txid, utxo_nout, ParseAmount(utxo_amount)};
    return *this;
}

CreateInscriptionBuilder &CreateInscriptionBuilder::AddFundMiningFee(const std::string &txid, uint32_t nout,
                                                                     const std::string& amount,
                                                                     const std::string& pk)
{
    m_xtra_utxo.emplace_back(std::string(txid), nout, ParseAmount(amount), unhex<xonly_pubkey>(pk));
    return *this;
}

CreateInscriptionBuilder &CreateInscriptionBuilder::MiningFeeRate(const std::string &rate)
{
    SetMiningFeeRate(rate);
    return *this;
}

CreateInscriptionBuilder &CreateInscriptionBuilder::Data(const std::string& content_type, const std::string &hex_data)
{
    m_content_type = content_type;
    m_content = unhex<bytevector>(hex_data);
    return *this;
}

CreateInscriptionBuilder &CreateInscriptionBuilder::DestinationPubKey(const std::string &pk)
{
    m_destination_pk = unhex<xonly_pubkey>(pk);
    return *this;
}

std::string CreateInscriptionBuilder::GetInscribeInternalPubKey() const
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
}

void CreateInscriptionBuilder::SignCommit(uint32_t n, const std::string& sk, const std::string& inscribe_script_pk)
{
    if (n >= m_utxo.size()) throw ContractTermMissing(name_utxo + '[' + std::to_string(n) + ']');
    CheckBuildArgs();

    auto utxo_it = m_utxo.begin();
    std::advance(utxo_it, n);
    core::ChannelKeys utxo_key(unhex<seckey>(sk));
    if (utxo_key.GetLocalPubKey() != utxo_it->m_pubkey) throw ContractValueMismatch(name_utxo + '[' + std::to_string(n) + ']' + name_pk);

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

const CScript& CreateInscriptionBuilder::GetInscriptionScript() const
{
    if (!mInscriptionScript || (m_collection_id.has_value() != mInscriptionScriptHasCollectionId)) {
        mInscriptionScript = MakeInscriptionScript(*m_inscribe_script_pk, *m_content_type, *m_content, m_collection_id);
        mInscriptionScriptHasCollectionId = m_collection_id.has_value();
    }
    return *mInscriptionScript;
}

std::vector<CTxOut> CreateInscriptionBuilder::GetGenesisTxSpends() const {
    std::vector<CTxOut> spending_outs;
    spending_outs.reserve(1 + (m_collection_utxo ? 1 : 0) + m_xtra_utxo.size());

    spending_outs.emplace_back(CommitTx().vout.front());
    if (m_collection_utxo) {
        spending_outs.emplace_back(m_collection_utxo->m_amount, CScript() << 1 << *m_collection_utxo->m_pubkey);
    }
    for (const auto& utxo: m_xtra_utxo) {
        spending_outs.emplace_back(utxo.m_amount, CScript() << 1 << *utxo.m_pubkey);
    }
    return spending_outs;
}

CMutableTransaction CreateInscriptionBuilder::PrepaireGenesisTx(bool to_sign)
{
    if (to_sign && !m_inscribe_taproot_sk) {
        const CScript& genesis_script = GetInscriptionScript();
        ScriptMerkleTree genesis_tap_tree(TreeBalanceType::WEIGHTED, {genesis_script});
        uint256 root = genesis_tap_tree.CalculateRoot();

        core::ChannelKeys inscribe_internal_key(*m_inscribe_int_sk);
        auto taproot = inscribe_internal_key.NewKeyAddTapTweak(root);
        m_inscribe_taproot_sk.emplace(taproot.first.GetLocalPrivKey());
    }

    const CMutableTransaction& commit_tx = CommitTx();

    CMutableTransaction genesis_tx = CreateGenesisTxTemplate();
    genesis_tx.vin[0].prevout.hash = commit_tx.GetHash();
    if (m_collection_utxo) {
        if (m_xtra_utxo.empty()) {
            genesis_tx.vin.pop_back();
        }

        genesis_tx.vout.front().nValue = commit_tx.vout.front().nValue;

        CAmount spend_amount = 0;
        auto gen_spends = GetGenesisTxSpends();
        for (const CTxOut &out: gen_spends) {
            spend_amount += out.nValue;
        }
        genesis_tx.vout[1].nValue = CalculateOutputAmount(spend_amount, *m_mining_fee_rate, genesis_tx) - genesis_tx.vout.front().nValue;
    }
    else {
        genesis_tx.vout.front().nValue = CalculateOutputAmount(commit_tx.vout.front().nValue, *m_mining_fee_rate, genesis_tx);
    }

    return genesis_tx;
}

void CreateInscriptionBuilder::SignCollection(const std::string& sk)
{
    CheckBuildArgs();

    if (!m_inscribe_script_pk) throw ContractStateError(std::string(name_inscribe_script_pk) + " undefined");
    if (!m_inscribe_int_sk) throw ContractStateError(std::string("internal inscription key undefined: has commit tx been signed?"));

    core::ChannelKeys collection_key(unhex<seckey>(sk));
    m_collection_utxo->m_pubkey = collection_key.GetLocalPubKey();

    CMutableTransaction genesis_tx = PrepaireGenesisTx(true);
    m_collection_utxo->m_sig = collection_key.SignTaprootTx(genesis_tx, 1, GetGenesisTxSpends(), {});
}

void CreateInscriptionBuilder::SignInscription(const std::string& insribe_script_sk)
{
    if (!m_inscribe_script_pk) throw ContractStateError(std::string(name_inscribe_script_pk) + " undefined");

    core::ChannelKeys script_keypair(unhex<seckey>(insribe_script_sk));
    if (*m_inscribe_script_pk != script_keypair.GetLocalPubKey()) throw ContractValueMismatch(std::string(name_inscribe_script_pk));

    if (!m_inscribe_int_sk) throw ContractStateError(std::string("internal inscription key undefined: has commit tx been signed?"));
    if (m_collection_utxo && !m_collection_utxo->m_pubkey) throw ContractStateError("Need signed collection input before inscription");

    CMutableTransaction genesis_tx = PrepaireGenesisTx(true);

    m_inscribe_script_sig = script_keypair.SignTaprootTx(genesis_tx, 0, GetGenesisTxSpends(), GetInscriptionScript());
}

void CreateInscriptionBuilder::SignFundMiningFee(uint32_t n, const string &sk)
{
    if (n >= m_xtra_utxo.size()) throw ContractTermMissing(name_xtra_utxo + '[' + std::to_string(n) + ']');
    if (!m_inscribe_script_pk) throw ContractStateError(std::string(name_inscribe_script_pk) + " undefined");
    if (!m_inscribe_int_sk) throw ContractStateError(std::string("internal inscription key undefined: has commit tx been signed?"));

    core::ChannelKeys keypair(unhex<seckey>(sk));
    auto xtra_it = m_xtra_utxo.begin();
    std::advance(xtra_it, n);

    if (keypair.GetLocalPubKey() != *xtra_it->m_pubkey) throw ContractValueMismatch(name_xtra_utxo + '[' + std::to_string(n) + ']' + name_pk);

    CMutableTransaction genesis_tx = PrepaireGenesisTx(true);

    uint32_t n_in = n + (m_collection_utxo ? 2 : 1);
    xtra_it->m_sig = keypair.SignTaprootTx(genesis_tx, n_in, GetGenesisTxSpends(), {});
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
        utxo_val.pushKV(name_txid, utxo.m_txid);
        utxo_val.pushKV(name_nout, utxo.m_nout);
        utxo_val.pushKV(name_amount, utxo.m_amount);
        utxo_val.pushKV(name_sig, hex(*utxo.m_sig));

        utxo_arr.push_back(move(utxo_val));
    }
    contract.pushKV(name_utxo, utxo_arr);

    if (m_collection_utxo) {
        UniValue collection_val(UniValue::VOBJ);
        collection_val.pushKV(name_txid, m_collection_utxo->m_txid);
        collection_val.pushKV(name_nout, m_collection_utxo->m_nout);
        collection_val.pushKV(name_amount, m_collection_utxo->m_amount);
        collection_val.pushKV(name_pk, hex(*m_collection_utxo->m_pubkey));
        collection_val.pushKV(name_sig, hex(*m_collection_utxo->m_sig));
        collection_val.pushKV(name_collection_id, *m_collection_id);
        contract.pushKV(name_collection, move(collection_val));
    }

    if (!m_xtra_utxo.empty()) {
        UniValue xtra_utxo_arr(UniValue::VARR);
        for (const auto &utxo: m_xtra_utxo) {
            UniValue utxo_val(UniValue::VOBJ);
            utxo_val.pushKV(name_txid, utxo.m_txid);
            utxo_val.pushKV(name_nout, utxo.m_nout);
            utxo_val.pushKV(name_amount, utxo.m_amount);
            utxo_val.pushKV(name_sig, hex(*utxo.m_sig));

            xtra_utxo_arr.push_back(move(utxo_val));
        }
        contract.pushKV(name_xtra_utxo, xtra_utxo_arr);
    }

    contract.pushKV(name_content_type, m_content_type.value());
    contract.pushKV(name_content, hex(m_content.value()));

    contract.pushKV(name_inscribe_script_pk, hex(m_inscribe_script_pk.value()));
    contract.pushKV(name_inscribe_int_pk, GetInscribeInternalPubKey());
    contract.pushKV(name_inscribe_sig, hex(m_inscribe_script_sig.value()));

    contract.pushKV(name_destination_pk, hex(m_destination_pk.value()));

    UniValue dataRoot(UniValue::VOBJ);
    dataRoot.pushKV(name_contract_type, val_create_inscription);
    dataRoot.pushKV(name_params, move(contract));

    return dataRoot.write();
}

void CreateInscriptionBuilder::Deserialize(const std::string &data)
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

            if (!utxo.exists(name_txid))
                throw ContractTermMissing(std::string(name_utxo) + '[' + std::to_string(n) + "]." + name_txid);
            if (!utxo.exists(name_nout))
                throw ContractTermMissing(std::string(name_utxo) + '[' + std::to_string(n) + "]." + name_nout);
            if (!utxo.exists(name_amount))
                throw ContractTermMissing(std::string(name_utxo) + '[' + std::to_string(n) + "]." + name_amount);
            if (!utxo.exists(name_sig))
                throw ContractTermMissing(std::string(name_utxo) + '[' + std::to_string(n) + "]." + name_sig);

            std::string txid = utxo[name_txid].get_str();
            uint32_t nout = utxo[name_nout].getInt<uint32_t>();
            CAmount amount = utxo[name_amount].getInt<CAmount>();
            signature sig = unhex<signature>(utxo[name_sig].get_str());

            m_utxo.emplace_back(move(txid), nout, amount);
            m_utxo.back().m_sig = move(sig);
        }
    }
    {   const auto &val = contract[name_collection];
        if (!val.isNull()) {
            if (!val.isObject()) throw ContractTermWrongFormat(std::string(name_collection));

            if (!val.exists(name_txid))
                throw ContractTermMissing(std::string(name_collection) + "." + name_txid);
            if (!val.exists(name_nout))
                throw ContractTermMissing(std::string(name_collection) + "." + name_nout);
            if (!val.exists(name_amount))
                throw ContractTermMissing(std::string(name_collection) + "." + name_amount);
            if (!val.exists(name_pk))
                throw ContractTermMissing(std::string(name_collection) + "." + name_pk);
            if (!val.exists(name_sig))
                throw ContractTermMissing(std::string(name_collection) + "." + name_sig);
            if (!val.exists(name_collection_id))
                throw ContractTermMissing(std::string(name_collection) + "." + name_collection_id);

            m_collection_id = val[name_collection_id].get_str();

            std::string txid = val[name_txid].get_str();
            uint32_t nout = val[name_nout].getInt<uint32_t>();
            CAmount amount = val[name_amount].getInt<CAmount>();
            xonly_pubkey pk = unhex<signature>(val[name_pk].get_str());
            signature sig = unhex<signature>(val[name_sig].get_str());

            m_collection_utxo = {move(txid), nout, amount, move(pk), move(sig)};
        }
    }
    {   const auto &val = contract[name_xtra_utxo];

        if (!val.isNull()) {
            if (!val.isArray()) throw ContractTermWrongFormat(std::string(name_xtra_utxo));

            for (size_t n = 0; n < val.size(); ++n) {
                const UniValue &utxo = val[n];

                if (!utxo.exists(name_txid))
                    throw ContractTermMissing(std::string(name_xtra_utxo) + '[' + std::to_string(n) + "]." + name_txid);
                if (!utxo.exists(name_nout))
                    throw ContractTermMissing(std::string(name_xtra_utxo) + '[' + std::to_string(n) + "]." + name_nout);
                if (!utxo.exists(name_amount))
                    throw ContractTermMissing(std::string(name_xtra_utxo) + '[' + std::to_string(n) + "]." + name_amount);
                if (!utxo.exists(name_sig))
                    throw ContractTermMissing(std::string(name_xtra_utxo) + '[' + std::to_string(n) + "]." + name_sig);

                std::string txid = utxo[name_txid].get_str();
                uint32_t nout = utxo[name_nout].getInt<uint32_t>();
                CAmount amount = utxo[name_amount].getInt<CAmount>();
                signature sig = unhex<signature>(utxo[name_sig].get_str());

                m_xtra_utxo.emplace_back(move(txid), nout, amount);
                m_xtra_utxo.back().m_sig = move(sig);
            }
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
    RestoreTransactions();
}

const CMutableTransaction& CreateInscriptionBuilder::CommitTx() const
{
    if (!mCommitTx) {
        if (m_utxo.empty()) throw ContractTermMissing(std::string(name_utxo));
        uint32_t n = 0;
        CAmount utxo_amount = 0;
        for (const auto& utxo: m_utxo) {
            if (!utxo.m_sig) throw ContractTermMissing(std::string(name_utxo) + '[' + std::to_string(n) + "]." + name_sig);
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
        if (!m_collection_utxo->m_pubkey) throw ContractTermMissing(std::string(name_collection) + '.' + name_pk);
        if (!m_collection_utxo->m_sig) throw ContractTermMissing(std::string(name_collection) + '.' + name_sig);
    }

    mGenesisTx = PrepaireGenesisTx(false);
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
        ScriptMerkleTree genesis_tap_tree(TreeBalanceType::WEIGHTED, {GetInscriptionScript()});
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

    CScript genesis_script = MakeInscriptionScript(m_inscribe_script_pk.value_or(emptyKey), *m_content_type, *m_content, m_collection_id);
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

    if (m_collection_utxo && m_xtra_utxo.empty()) {
        result.vin.emplace_back(uint256(), 0);
        result.vin.back().scriptWitness.stack.emplace_back(signature());
    }
    else {
        for (const auto &utxo: m_xtra_utxo) {
            result.vin.emplace_back(uint256S(utxo.m_txid), utxo.m_nout);
            result.vin.back().scriptWitness.stack.emplace_back(utxo.m_sig.value_or(signature()));
        }
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

std::string CreateInscriptionBuilder::GetGenesisTxMiningFee() const
{
    return FormatAmount(CalculateTxFee(*m_mining_fee_rate, CreateGenesisTxTemplate()));
}

}
