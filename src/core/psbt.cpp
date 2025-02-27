// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "psbt.hpp"

#include "policy/policy.h"
#include <wrapstream.hpp>

#include "base64.hpp"

namespace l15::core {

namespace {
// Magic bytes
constexpr uint8_t PSBT_MAGIC_BYTES[5] = {'p', 's', 'b', 't', 0xff};

// Global types
constexpr uint8_t PSBT_GLOBAL_UNSIGNED_TX = 0x00;
constexpr uint8_t PSBT_GLOBAL_XPUB = 0x01;
constexpr uint8_t PSBT_GLOBAL_TX_VERSION = 0x02;
constexpr uint8_t PSBT_GLOBAL_FALLBACK_LOCKTIME = 0x03;
constexpr uint8_t PSBT_GLOBAL_INPUT_COUNT = 0x04;
constexpr uint8_t PSBT_GLOBAL_OUTPUT_COUNT = 0x05;
constexpr uint8_t PSBT_GLOBAL_VERSION = 0xFB;
constexpr uint8_t PSBT_GLOBAL_PROPRIETARY = 0xFC;

// Input types
constexpr uint8_t PSBT_IN_NON_WITNESS_UTXO = 0x00;
constexpr uint8_t PSBT_IN_WITNESS_UTXO = 0x01;
constexpr uint8_t PSBT_IN_PARTIAL_SIG = 0x02;
constexpr uint8_t PSBT_IN_SIGHASH = 0x03;
constexpr uint8_t PSBT_IN_REDEEMSCRIPT = 0x04;
constexpr uint8_t PSBT_IN_WITNESSSCRIPT = 0x05;
constexpr uint8_t PSBT_IN_BIP32_DERIVATION = 0x06;
constexpr uint8_t PSBT_IN_SCRIPTSIG = 0x07;
constexpr uint8_t PSBT_IN_SCRIPTWITNESS = 0x08;
constexpr uint8_t PSBT_IN_RIPEMD160 = 0x0A;
constexpr uint8_t PSBT_IN_SHA256 = 0x0B;
constexpr uint8_t PSBT_IN_HASH160 = 0x0C;
constexpr uint8_t PSBT_IN_HASH256 = 0x0D;
constexpr uint8_t PSBT_IN_TAP_KEY_SIG = 0x13;
constexpr uint8_t PSBT_IN_TAP_SCRIPT_SIG = 0x14;
constexpr uint8_t PSBT_IN_TAP_LEAF_SCRIPT = 0x15;
constexpr uint8_t PSBT_IN_TAP_BIP32_DERIVATION = 0x16;
constexpr uint8_t PSBT_IN_TAP_INTERNAL_KEY = 0x17;
constexpr uint8_t PSBT_IN_TAP_MERKLE_ROOT = 0x18;
constexpr uint8_t PSBT_IN_PROPRIETARY = 0xFC;

// Output types
constexpr uint8_t PSBT_OUT_REDEEMSCRIPT = 0x00;
constexpr uint8_t PSBT_OUT_WITNESSSCRIPT = 0x01;
constexpr uint8_t PSBT_OUT_BIP32_DERIVATION = 0x02;
constexpr uint8_t PSBT_OUT_TAP_INTERNAL_KEY = 0x05;
constexpr uint8_t PSBT_OUT_TAP_TREE = 0x06;
constexpr uint8_t PSBT_OUT_TAP_BIP32_DERIVATION = 0x07;
constexpr uint8_t PSBT_OUT_PROPRIETARY = 0xFC;

// The separator is 0x00. Reading this in means that the unserializer can interpret it
// as a 0 length key which indicates that this is the separator. The separator has no value.
constexpr uint8_t PSBT_SEPARATOR = 0x00;

// BIP 174 does not specify a maximum file size, but we set a limit anyway
// to prevent reading a stream indefinitely and running out of memory.
const std::streamsize MAX_FILE_SIZE_PSBT = 100000000; // 100 MB

// PSBT version number
constexpr uint32_t PSBT_HIGHEST_VERSION = 2;


// Takes a stream and multiple arguments and serializes them as if first serialized into a vector and then into the stream
// The resulting output into the stream has the total serialized length of all of the objects followed by all objects concatenated with each other.
template<typename Stream, typename... X>
void SerializeAsValue(Stream& s, const X&... args)
{
    SizeComputer sizecomp;
    SerializeMany(sizecomp, args...);
    WriteCompactSize(s, sizecomp.size());
    SerializeMany(s, args...);
}

// Takes a stream and multiple arguments and deserializes them first as a vector then each object individually in the order provided in the arguments
template<typename Stream, typename... X>
void DeserializeAsValue(Stream& s, X&&... args)
{
    size_t expected_size = ReadCompactSize(s);
    size_t remaining_before = s.size();
    UnserializeMany(s, args...);
    size_t remaining_after = s.size();
    if (remaining_after + expected_size != remaining_before) {
        throw TransactionError("Size of value was not the stated size");
    }
}

// Deserialize bytes of given length from the stream as a KeyOriginInfo
template<typename Stream>
KeyOriginInfo DeserializeKeyOrigin(Stream& s, uint64_t length)
{
    // Read in key path
    if (length % 4 || length == 0) {
        throw TransactionError("Invalid length for HD key path");
    }

    KeyOriginInfo hd_keypath;
    s >> hd_keypath.fingerprint;
    for (unsigned int i = 4; i < length; i += sizeof(uint32_t)) {
        uint32_t index;
        s >> index;
        hd_keypath.path.push_back(index);
    }
    return hd_keypath;
}

// Deserialize a length prefixed KeyOriginInfo from a stream
template<typename Stream>
void DeserializeHDKeypath(Stream& s, KeyOriginInfo& hd_keypath)
{
    hd_keypath = DeserializeKeyOrigin(s, ReadCompactSize(s));
}

// Deserialize HD keypaths into a map
template<typename Stream>
void DeserializeHDKeypaths(Stream& s, const bytevector& key, std::map<compressed_pubkey, KeyOriginInfo>& hd_keypaths)
{
    // Make sure that the key is the size of pubkey + 1
    if (key.size() != compressed_pubkey::SIZE + 1) {
        throw KeyError("Size of key was not the expected size for the type BIP32 keypath");
    }
    // Read in the pubkey from key
    compressed_pubkey pubkey(key.begin() + 1, key.end());
    // if (!pubkey.IsFullyValid()) {
    //    throw TransactionError("Invalid pubkey");
    // }
    if (hd_keypaths.count(pubkey) > 0) {
        throw TransactionError("Duplicate Key, pubkey derivation path already provided");
    }

    KeyOriginInfo keypath;
    DeserializeHDKeypath(s, keypath);

    // Add to map
    hd_keypaths.emplace(move(pubkey), std::move(keypath));
}

// Serialize a KeyOriginInfo to a stream
template<typename Stream>
void SerializeKeyOrigin(Stream& s, KeyOriginInfo hd_keypath)
{
    s << hd_keypath.fingerprint;
    for (const auto& path : hd_keypath.path) {
        s << path;
    }
}

// Serialize a length prefixed KeyOriginInfo to a stream
template<typename Stream>
void SerializeHDKeypath(Stream& s, KeyOriginInfo hd_keypath)
{
    WriteCompactSize(s, (hd_keypath.path.size() + 1) * sizeof(uint32_t));
    SerializeKeyOrigin(s, hd_keypath);
}

// Serialize HD keypaths to a stream from a map
template<typename Stream>
void SerializeHDKeypaths(Stream& s, const std::map<compressed_pubkey, KeyOriginInfo>& hd_keypaths, CompactSizeWriter type)
{
    for (const auto& keypath_pair : hd_keypaths) {
        // if (!keypath_pair.first.IsValid()) {
        //     throw WrongKey("Invalid pubkey being serialized");
        // }
        SerializeAsValue(s, type, Span{keypath_pair.first});
        SerializeHDKeypath(s, keypath_pair.second);
    }
}


}

PSBT::PSBT(const CMutableTransaction& tx) : base_tx(tx)
{
    for (auto& in: base_tx->vin) {
        in.scriptSig.clear();
        in.scriptWitness.stack.clear();
    }
    inputs.resize(tx.vin.size());
    outputs.resize(tx.vout.size());
}

bool PSBT::IsNull() const
{
    return !base_tx && inputs.empty() && outputs.empty() && unknown.empty();
}

bool PSBT::Merge(const PSBT& psbt)
{
    // Prohibited to merge two PSBTs over different transactions
    if (base_tx->GetHash() != psbt.base_tx->GetHash()) {
        return false;
    }

    for (unsigned int i = 0; i < inputs.size(); ++i) {
        inputs[i].Merge(psbt.inputs[i]);
    }
    for (unsigned int i = 0; i < outputs.size(); ++i) {
        outputs[i].Merge(psbt.outputs[i]);
    }
    // for (auto& xpub_pair : psbt.m_xpubs) {
    //     if (m_xpubs.count(xpub_pair.first) == 0) {
    //         m_xpubs[xpub_pair.first] = xpub_pair.second;
    //     } else {
    //         m_xpubs[xpub_pair.first].insert(xpub_pair.second.begin(), xpub_pair.second.end());
    //     }
    // }
    unknown.insert(psbt.unknown.begin(), psbt.unknown.end());

    return true;
}

bool PSBT::AddInput(const CTxIn& txin, PSBTInput& psbtin)
{
    if (std::find(base_tx->vin.begin(), base_tx->vin.end(), txin) != base_tx->vin.end()) {
        return false;
    }
    base_tx->vin.push_back(txin);
    psbtin.partial_sigs.clear();
    psbtin.final_script_sig.reset();
    psbtin.final_script_witness.reset();
    inputs.push_back(psbtin);
    return true;
}

bool PSBT::AddOutput(const CTxOut& txout, const PSBTOutput& psbtout)
{
    base_tx->vout.push_back(txout);
    outputs.push_back(psbtout);
    return true;
}

const CTxOut& PSBT::GetInputUTXO(size_t input_index) const
{
    const PSBTInput& input = inputs[input_index];
    uint32_t prevout_index = base_tx->vin[input_index].prevout.n;
    if (input.non_witness_utxo) {
        if (prevout_index >= input.non_witness_utxo->vout.size()) {
            throw std::out_of_range("UTXO not found");
        }
        if (input.non_witness_utxo->GetHash() != base_tx->vin[input_index].prevout.hash) {
            throw std::out_of_range("UTXO not found");
        }
        return input.non_witness_utxo->vout[prevout_index];
    }
    if (input.witness_utxo) {
        return  *input.witness_utxo;
    }
    throw std::out_of_range("UTXO not found");
}

void PSBT::Serialize(DataStream &s) const
{
    s << PSBT_MAGIC_BYTES;

    switch (m_version) {
    case 0:
        SerializeAsValue(s, CompactSizeWriter(PSBT_GLOBAL_UNSIGNED_TX));
        SerializeAsValue(s, TX_NO_WITNESS(*base_tx));

        if (m_fallback_locktime) throw TransactionError("Fallback locktime in PSBT v0");
        break;
    case 2:
        SerializeAsValue(s, CompactSizeWriter(PSBT_GLOBAL_TX_VERSION));
        SerializeAsValue(s, base_tx->nVersion);

        if (m_fallback_locktime) {
            SerializeAsValue(s, CompactSizeWriter(PSBT_GLOBAL_FALLBACK_LOCKTIME));
            SerializeAsValue(s, *m_fallback_locktime);
        }

        SerializeAsValue(s, CompactSizeWriter(PSBT_GLOBAL_INPUT_COUNT));
        SerializeAsValue(s, CompactSizeWriter(base_tx->vin.size()));

        SerializeAsValue(s, CompactSizeWriter(PSBT_GLOBAL_OUTPUT_COUNT));
        SerializeAsValue(s, CompactSizeWriter(base_tx->vout.size()));
        break;
    }

    //Write xpubs
    // for (const auto& xpub_pair : m_xpubs) {
    //     for (const auto& xpub : xpub_pair.second) {
    //         unsigned char ser_xpub[BIP32_EXTKEY_WITH_VERSION_SIZE];
    //         xpub.EncodeWithVersion(ser_xpub);
    //         // Note that the serialization swaps the key and value
    //         // The xpub is the key (for uniqueness) while the path is the value
    //         SerializeToVector(s, PSBT_GLOBAL_XPUB, ser_xpub);
    //         SerializeHDKeypath(s, xpub_pair.first);
    //     }
    // }

    // PSBT version
    if (GetVersion() > 0) {
        SerializeAsValue(s, CompactSizeWriter(PSBT_GLOBAL_VERSION));
        SerializeAsValue(s, m_version);
    }

    // Write proprietary things
    for (const auto &entry: m_proprietary) {
        s << entry.key;
        s << entry.value;
    }

    // Write the unknown things
    for (auto &entry: unknown) {
        s << entry.first;
        s << entry.second;
    }

    // Separator
    s << PSBT_SEPARATOR;

    // Write inputs
    for (const PSBTInput &input: inputs) {
        input.Serialize(s);
    }
    // Write outputs
    for (const PSBTOutput &output: outputs) {
        output.Serialize(s);
    }

}

void PSBT::Deserialize(DataStream &s)
{
    uint8_t magic[5];
    s >> magic;
    if (!std::equal(magic, magic + 5, PSBT_MAGIC_BYTES)) throw TransactionError("Invalid PSBT magic bytes");

    std::set<bytevector> key_lookup;

    // Track the global xpubs we have already seen. Just for sanity checking
    //std::set<CExtPubKey> global_xpubs;

    // Read global data
    bool found_sep = false;
    while (!s.empty()) {
        // Read
        bytevector key;
        s >> key;

        // the key is empty if that was actually a separator byte
        // This is a special case for key lengths 0 as those are not allowed (except for separator)
        if (key.empty()) {
            found_sep = true;
            break;
        }

        // Type is compact size uint at beginning of key
        SpanReader skey{key};
        uint64_t type = ReadCompactSize(skey);

        // Do stuff based on type
        switch (type) {
        case PSBT_GLOBAL_UNSIGNED_TX: {
            if (m_version == 2) throw TransactionError("Unsigned Transaction is not allowed for PSBT v2");
            if (!key_lookup.emplace(key).second) throw TransactionError("Duplicate Key, unsigned tx already provided");
            if (key.size() != 1) throw TransactionError("Global unsigned tx key is more than one byte type");

            CMutableTransaction mtx;
            // Set the stream to serialize with non-witness since this should always be non-witness
            DeserializeAsValue(s, TX_NO_WITNESS(mtx));
            base_tx = std::move(mtx);
            // Make sure that all scriptSigs and scriptWitnesses are empty
            for (const CTxIn &txin: base_tx->vin) {
                if (!txin.scriptSig.empty() || !txin.scriptWitness.IsNull())
                    throw TransactionError("Unsigned tx does not have empty scriptSigs and scriptWitnesses.");
            }
            break;
        }
        case PSBT_GLOBAL_XPUB: {
            // if (key.size() != BIP32_EXTKEY_WITH_VERSION_SIZE + 1) {
            //     throw TransactionError("Size of key was not the expected size for the type global xpub");
            // }
            // // Read in the xpub from key
            // CExtPubKey xpub;
            // xpub.DecodeWithVersion(&key.data()[1]);
            // if (!xpub.pubkey.IsFullyValid()) {
            //    throw TransactionError("Invalid pubkey");
            // }
            // if (global_xpubs.count(xpub) > 0) {
            //    throw TransactionError("Duplicate key, global xpub already provided");
            // }
            // global_xpubs.insert(xpub);
            // // Read in the keypath from stream
            // KeyOriginInfo keypath;
            // DeserializeHDKeypath(s, keypath);
            //
            // // Note that we store these swapped to make searches faster.
            // // Serialization uses xpub -> keypath to enqure key uniqueness
            // if (m_xpubs.count(keypath) == 0) {
            //     // Make a new set to put the xpub in
            //     m_xpubs[keypath] = {xpub};
            // } else {
            //     // Insert xpub into existing set
            //     m_xpubs[keypath].insert(xpub);
            // }
            break;
        }
        case PSBT_GLOBAL_TX_VERSION:
            if (!key_lookup.emplace(key).second) throw TransactionError("Duplicate Key, unsigned tx already provided");
            if (key.size() != 1) throw TransactionError("Global unsigned tx key is more than one byte type");

            if (!base_tx) base_tx.emplace();
            DeserializeAsValue(s, base_tx->nVersion);

            break;
        case PSBT_GLOBAL_FALLBACK_LOCKTIME:
            if (m_fallback_locktime) throw TransactionError("Duplicate Key, fallback locktime already provided");
            if (key.size() != 1) throw TransactionError("Fallback locktime key is more than one byte type");

            m_fallback_locktime.emplace();
            DeserializeAsValue(s, *m_fallback_locktime);

            break;
        case PSBT_GLOBAL_INPUT_COUNT:
            if (!key_lookup.emplace(key).second) throw TransactionError("Duplicate Key, input count already provided");
            if (key.size() != 1) throw TransactionError("Input count key is more than one byte type"); {
                uint64_t len = ReadCompactSize(s);
                size_t before = s.size();
                if (!base_tx) base_tx.emplace();
                base_tx->vin.resize(ReadCompactSize(s));
                //inputs.resize(tx->vin.size());

                if (s.size() + len != before) throw TransactionError("Input count value length mismatch");
            }
            break;
        case PSBT_GLOBAL_OUTPUT_COUNT:
            if (!key_lookup.emplace(key).second) throw TransactionError("Duplicate Key, output count already provided");
            if (key.size() != 1) throw TransactionError("Output count key is more than one byte type"); {
                uint64_t len = ReadCompactSize(s);
                size_t before = s.size();
                if (!base_tx) base_tx.emplace();
                base_tx->vout.resize(ReadCompactSize(s));
                //outputs.resize(tx->vout.size());

                if (s.size() + len != before) throw TransactionError("Output count value length mismatch");
            }
            break;

        case PSBT_GLOBAL_VERSION:
            if (!key_lookup.emplace(key).second) throw TransactionError("Duplicate Key, version already provided");
            if (key.size() != 1) throw TransactionError("Global version key is more than one byte type");

            DeserializeAsValue(s, m_version);
            if (m_version > PSBT_HIGHEST_VERSION) throw TransactionError("Unsupported version number");

            break;
        case PSBT_GLOBAL_PROPRIETARY: {
            PSBTProprietary this_prop;
            skey >> this_prop.identifier;
            this_prop.subtype = ReadCompactSize(skey);
            this_prop.key = key;

            if (m_proprietary.count(this_prop) > 0) throw TransactionError( "Duplicate Key, proprietary key already found");

            s >> this_prop.value;
            m_proprietary.insert(this_prop);
            break;
        }
        // Unknown stuff
        default: {
            if (unknown.count(key) > 0) throw TransactionError("Duplicate Key, key for unknown value already provided");

            // Read in the value
            bytevector val_bytes;
            s >> val_bytes;
            unknown.emplace(std::move(key), std::move(val_bytes));
        }
        }
    }

    if (!found_sep) throw TransactionError("Separator is missing at the end of the global map");

    // Make sure that we got an unsigned tx
    if (!base_tx) throw TransactionError("No unsigned transaction was provided");

    // Read input data
    unsigned int i = 0;
    while (!s.empty() && i < base_tx->vin.size()) {
        inputs.emplace_back(PSBTInput(s));

        // Make sure the non-witness utxo matches the outpoint
        if (inputs.back().non_witness_utxo && inputs.back().non_witness_utxo->GetHash() != base_tx->vin[i].prevout.hash)
            throw TransactionError("Non-witness UTXO does not match outpoint hash");

        ++i;
    }
    // Make sure that the number of inputs matches the number of inputs in the transaction
    if (inputs.size() != base_tx->vin.size()) throw TransactionError( "Inputs provided does not match the number of inputs in transaction.");

    // Read output data
    i = 0;
    while (!s.empty() && i < base_tx->vout.size()) {
        outputs.emplace_back(PSBTOutput(s));
        ++i;
    }
    // Make sure that the number of outputs matches the number of outputs in the transaction
    if (outputs.size() != base_tx->vout.size()) throw TransactionError( "Outputs provided does not match the number of outputs in transaction.");

}

bool PSBTInput::IsNull() const
{
    return !non_witness_utxo && !witness_utxo && partial_sigs.empty() && unknown.empty() && hd_keypaths.empty() && !redeem_script && !witness_script;
}

void PSBTInput::Merge(const PSBTInput& input)
{
    if (!non_witness_utxo && input.non_witness_utxo)
        non_witness_utxo = input.non_witness_utxo;

    if (!witness_utxo && input.witness_utxo)
        witness_utxo = input.witness_utxo;

    partial_sigs.insert(input.partial_sigs.begin(), input.partial_sigs.end());
    ripemd160_preimages.insert(input.ripemd160_preimages.begin(), input.ripemd160_preimages.end());
    sha256_preimages.insert(input.sha256_preimages.begin(), input.sha256_preimages.end());
    hash160_preimages.insert(input.hash160_preimages.begin(), input.hash160_preimages.end());
    hash256_preimages.insert(input.hash256_preimages.begin(), input.hash256_preimages.end());
    hd_keypaths.insert(input.hd_keypaths.begin(), input.hd_keypaths.end());
    unknown.insert(input.unknown.begin(), input.unknown.end());
    m_tap_script_sigs.insert(input.m_tap_script_sigs.begin(), input.m_tap_script_sigs.end());
    m_tap_scripts.insert(input.m_tap_scripts.begin(), input.m_tap_scripts.end());
    m_tap_bip32_paths.insert(input.m_tap_bip32_paths.begin(), input.m_tap_bip32_paths.end());

    if (!redeem_script && input.redeem_script)
        redeem_script = input.redeem_script;

    if (!witness_script && input.witness_script)
        witness_script = input.witness_script;

    if (!final_script_sig && input.final_script_sig)
        final_script_sig = input.final_script_sig;

    if (!final_script_witness && input.final_script_witness)
        final_script_witness = input.final_script_witness;

    if (!m_tap_key_sig && input.m_tap_key_sig)
        m_tap_key_sig = input.m_tap_key_sig;

    if (!m_tap_internal_key && input.m_tap_internal_key)
        m_tap_internal_key = input.m_tap_internal_key;

    if (!m_tap_merkle_root && input.m_tap_merkle_root)
        m_tap_merkle_root = input.m_tap_merkle_root;
}

void PSBTInput::Serialize(DataStream &s) const
{
    // Write the utxo
    if (non_witness_utxo) {
        SerializeAsValue(s, CompactSizeWriter(PSBT_IN_NON_WITNESS_UTXO));
        SerializeAsValue(s, TX_WITH_WITNESS(non_witness_utxo));
    }
    if (witness_utxo) {
        SerializeAsValue(s, CompactSizeWriter(PSBT_IN_WITNESS_UTXO));
        SerializeAsValue(s, *witness_utxo);
    }

    if (!final_script_sig.has_value() && !final_script_witness.has_value()) {
        // Write any partial signatures
        for (auto sig_pair: partial_sigs) {
            SerializeAsValue(s, CompactSizeWriter(PSBT_IN_PARTIAL_SIG), Span{sig_pair.second.first});
            s << sig_pair.second.second;
        }

        // Write the sighash type
        if (sighash_type != std::nullopt) {
            SerializeAsValue(s, CompactSizeWriter(PSBT_IN_SIGHASH));
            SerializeAsValue(s, *sighash_type);
        }

        // Write the redeem script
        if (redeem_script) {
            SerializeAsValue(s, CompactSizeWriter(PSBT_IN_REDEEMSCRIPT));
            s << *redeem_script;
        }

        // Write the witness script
        if (witness_script) {
            SerializeAsValue(s, CompactSizeWriter(PSBT_IN_WITNESSSCRIPT));
            s << *witness_script;
        }

        // Write any hd keypaths
        SerializeHDKeypaths(s, hd_keypaths, CompactSizeWriter(PSBT_IN_BIP32_DERIVATION));

        // Write any ripemd160 preimage
        for (const auto &[hash, preimage]: ripemd160_preimages) {
            SerializeAsValue(s, CompactSizeWriter(PSBT_IN_RIPEMD160), hash);
            s << preimage;
        }

        // Write any sha256 preimage
        for (const auto &[hash, preimage]: sha256_preimages) {
            SerializeAsValue(s, CompactSizeWriter(PSBT_IN_SHA256), hash);
            s << preimage;
        }

        // Write any hash160 preimage
        for (const auto &[hash, preimage]: hash160_preimages) {
            SerializeAsValue(s, CompactSizeWriter(PSBT_IN_HASH160), hash);
            s << preimage;
        }

        // Write any hash256 preimage
        for (const auto &[hash, preimage]: hash256_preimages) {
            SerializeAsValue(s, CompactSizeWriter(PSBT_IN_HASH256), hash);
            s << preimage;
        }

        // Write taproot key sig
        if (m_tap_key_sig) {
            SerializeAsValue(s, CompactSizeWriter(PSBT_IN_TAP_KEY_SIG));
            s << *m_tap_key_sig;
        }

        // Write taproot script sigs
        for (const auto &[pubkey_leaf, sig]: m_tap_script_sigs) {
            const auto &[pk, leaf_hash] = pubkey_leaf;
            SerializeAsValue(s, CompactSizeWriter(PSBT_IN_TAP_SCRIPT_SIG), Span(pk), leaf_hash);
            s << sig;
        }

        // Write taproot leaf scripts
        for (const auto &[script, control_block]: m_tap_scripts) {
            SerializeAsValue(s, CompactSizeWriter(PSBT_IN_TAP_LEAF_SCRIPT), Span(control_block));
            bytevector value_v(script.begin(), script.end());
            value_v.push_back(0x0C0);
            s << value_v;
        }

        // Write taproot bip32 keypaths
        for (const auto &[pk, leaf_origin]: m_tap_bip32_paths) {
            const auto &[leaf_hashes, origin] = leaf_origin;
            SerializeAsValue(s, CompactSizeWriter(PSBT_IN_TAP_BIP32_DERIVATION), Span(pk));
            bytevector value;
            VectorWriter s_value{value, 0};
            s_value << leaf_hashes;
            SerializeKeyOrigin(s_value, origin);
            s << value;
        }

        // Write taproot internal key
        if (m_tap_internal_key) {
            SerializeAsValue(s, CompactSizeWriter(PSBT_IN_TAP_INTERNAL_KEY));
            s << m_tap_internal_key->get_vector();
        }

        // Write taproot merkle root
        if (m_tap_merkle_root) {
            SerializeAsValue(s, CompactSizeWriter(PSBT_IN_TAP_MERKLE_ROOT));
            SerializeAsValue(s, *m_tap_merkle_root);
        }
    }

    // Write script sig
    if (final_script_sig) {
        SerializeAsValue(s, CompactSizeWriter(PSBT_IN_SCRIPTSIG));
        s << *final_script_sig;
    }
    // write script witness
    if (final_script_witness) {
        SerializeAsValue(s, CompactSizeWriter(PSBT_IN_SCRIPTWITNESS));
        SerializeAsValue(s, final_script_witness->stack);
    }

    // Write proprietary things
    for (const auto &entry: m_proprietary) {
        s << entry.key;
        s << entry.value;
    }

    // Write unknown things
    for (auto &entry: unknown) {
        s << entry.first;
        s << entry.second;
    }

    s << PSBT_SEPARATOR;
}

void PSBTInput::Deserialize(DataStream& s)
{
    std::set<bytevector> key_lookup;

    bool found_sep = false;
    while (!s.empty()) {
        bytevector key;
        s >> key;

        // the key is empty if that was actually a separator byte
        // This is a special case for key lengths 0 as those are not allowed (except for separator)
        if (key.empty()) {
            found_sep = true;
            break;
        }

        auto skey = cex::make_stream(key);
        uint64_t type = ReadCompactSize(skey);

        switch (type) {
        case PSBT_IN_NON_WITNESS_UTXO: {
            if (!key_lookup.emplace(key).second) throw TransactionError(
                "Duplicate Key, input non-witness utxo already provided");
            if (key.size() != 1) throw TransactionError("Non-witness utxo key is more than one byte type");

            // Set the stream to unserialize with witness since this is always a valid network transaction
            DeserializeAsValue(s, TX_WITH_WITNESS(non_witness_utxo));
            break;
        }
        case PSBT_IN_WITNESS_UTXO: {
            if (!key_lookup.emplace(key).second) throw TransactionError(
                "Duplicate Key, input witness utxo already provided");
            if (key.size() != 1) throw TransactionError("Witness utxo key is more than one byte type");

            witness_utxo.emplace();
            DeserializeAsValue(s, *witness_utxo);
            break;
        }
        case PSBT_IN_PARTIAL_SIG: {
            if (key.size() != compressed_pubkey::SIZE + 1) throw KeyError(
                "Size of key was not the expected size for the type partial signature pubkey");

            compressed_pubkey pubkey(key.begin() + 1, key.end());
            // if (!pubkey.IsFullyValid()) {
            //    throw TransactionError("Invalid pubkey");
            // }

            bytevector keyId = cryptohash<bytevector>(pubkey, CHash160());
            if (partial_sigs.contains(keyId)) throw TransactionError(
                "Duplicate Key, input partial signature for pubkey already provided");

            // Read in the signature from value
            bytevector sig;
            s >> sig;

            partial_sigs.emplace(keyId, std::make_pair(pubkey, std::move(sig)));
            break;
        }
        case PSBT_IN_SIGHASH: {
            if (!key_lookup.emplace(key).second) throw TransactionError(
                "Duplicate Key, input sighash type already provided");
            if (key.size() != 1) throw TransactionError("Sighash type key is more than one byte type");

            int sighash;
            DeserializeAsValue(s, sighash);
            sighash_type = sighash;
            break;
        }
        case PSBT_IN_REDEEMSCRIPT: {
            if (!key_lookup.emplace(key).second) throw TransactionError(
                "Duplicate Key, input redeemScript already provided");
            if (key.size() != 1) throw TransactionError("Input redeemScript key is more than one byte type");

            CScript script;
            s >> script;
            redeem_script.emplace(script.begin(), script.end());
            break;
        }
        case PSBT_IN_WITNESSSCRIPT: {
            if (!key_lookup.emplace(key).second) throw TransactionError(
                "Duplicate Key, input witnessScript already provided");
            if (key.size() != 1) throw TransactionError("Input witnessScript key is more than one byte type");

            CScript script;
            s >> script;
            witness_script.emplace(script.begin(), script.end());
            break;
        }
        case PSBT_IN_BIP32_DERIVATION: {
            DeserializeHDKeypaths(s, key, hd_keypaths);
            break;
        }
        case PSBT_IN_SCRIPTSIG: {
            if (!key_lookup.emplace(key).second) throw TransactionError(
                "Duplicate Key, input final scriptSig already provided");
            if (key.size() != 1) throw TransactionError("Final scriptSig key is more than one byte type");

            CScript script;
            s >> script;
            final_script_sig.emplace(script.begin(), script.end());
            break;
        }
        case PSBT_IN_SCRIPTWITNESS: {
            if (!key_lookup.emplace(key).second) throw TransactionError(
                "Duplicate Key, input final scriptWitness already provided");
            if (key.size() != 1) throw TransactionError("Final scriptWitness key is more than one byte type");

            final_script_witness.emplace();
            DeserializeAsValue(s, final_script_witness->stack);
            break;
        }
        case PSBT_IN_RIPEMD160: {
            // Make sure that the key is the size of a ripemd160 hash + 1
            if (key.size() != CRIPEMD160::OUTPUT_SIZE + 1) throw TransactionError(
                "Size of key was not the expected size for the type ripemd160 preimage");

            // Read in the hash from key
            uint160 hash(std::span(key.begin() + 1, key.end()));
            if (ripemd160_preimages.contains(hash)) {
                throw TransactionError("Duplicate Key, input ripemd160 preimage already provided");
            }

            // Read in the preimage from value
            bytevector preimage;
            s >> preimage;

            // Add to preimages list
            ripemd160_preimages.emplace(move(hash), std::move(preimage));
            break;
        }
        case PSBT_IN_SHA256: {
            // Make sure that the key is the size of a sha256 hash + 1
            if (key.size() != CSHA256::OUTPUT_SIZE + 1) throw TransactionError(
                "Size of key was not the expected size for the type sha256 preimage");

            // Read in the hash from key
            uint256 hash(std::span(key.begin() + 1, key.end()));
            if (sha256_preimages.contains(hash)) throw TransactionError(
                "Duplicate Key, input sha256 preimage already provided");

            // Read in the preimage from value
            bytevector preimage;
            s >> preimage;

            // Add to preimages list
            sha256_preimages.emplace(move(hash), std::move(preimage));
            break;
        }
        case PSBT_IN_HASH160: {
            // Make sure that the key is the size of a hash160 hash + 1
            if (key.size() != CHash160::OUTPUT_SIZE + 1) throw TransactionError(
                "Size of key was not the expected size for the type hash160 preimage");

            // Read in the hash from key
            uint160 hash(std::span(key.begin() + 1, key.end()));
            if (hash160_preimages.contains(hash)) throw TransactionError(
                "Duplicate Key, input hash160 preimage already provided");

            // Read in the preimage from value
            bytevector preimage;
            s >> preimage;

            // Add to preimages list
            hash160_preimages.emplace(move(hash), std::move(preimage));
            break;
        }
        case PSBT_IN_HASH256: {
            // Make sure that the key is the size of a hash256 hash + 1
            if (key.size() != CHash256::OUTPUT_SIZE + 1) throw TransactionError(
                "Size of key was not the expected size for the type hash256 preimage");

            // Read in the hash from key
            uint256 hash(std::span(key.begin() + 1, key.end()));
            if (hash256_preimages.contains(hash)) throw TransactionError(
                "Duplicate Key, input hash256 preimage already provided");

            // Read in the preimage from value
            bytevector preimage;
            s >> preimage;

            // Add to preimages list
            hash256_preimages.emplace(move(hash), std::move(preimage));
            break;
        }
        case PSBT_IN_TAP_KEY_SIG: {
            if (!key_lookup.emplace(key).second) throw TransactionError(
                "Duplicate Key, input Taproot key signature already provided");
            if (key.size() != 1) throw TransactionError("Input Taproot key signature key is more than one byte type");

            signature sig;
            s >> sig;

            if (sig.size() < 64) throw TransactionError("Input Taproot key path signature is shorter than 64 bytes");
            if (sig.size() > 65) throw TransactionError("Input Taproot key path signature is longer than 65 bytes");

            m_tap_key_sig = move(sig);
            break;
        }
        case PSBT_IN_TAP_SCRIPT_SIG: {
            if (!key_lookup.emplace(key).second) throw TransactionError(
                "Duplicate Key, input Taproot script signature already provided");
            if (key.size() != 65) throw TransactionError("Input Taproot script signature key is not 65 bytes");

            xonly_pubkey pk;
            uint256 hash;
            skey.read(pk);
            skey.read(hash);

            signature sig;
            s >> sig;

            if (sig.size() < 64) throw TransactionError("Input Taproot script path signature is shorter than 64 bytes");
            if (sig.size() > 65) throw TransactionError("Input Taproot script path signature is longer than 65 bytes");

            m_tap_script_sigs.emplace(std::make_pair(move(pk), hash), move(sig));
            break;
        }
        case PSBT_IN_TAP_LEAF_SCRIPT: {
            //tapscript control block has length 32 * n + 1
            if (!key_lookup.emplace(key).second) throw TransactionError(
                "Duplicate Key, input Taproot leaf script already provided");
            if (skey.remains() < 33) throw TransactionError("Taproot leaf script key is not at least 34 bytes");
            if ((skey.remains() - 1) % 32 != 0) throw TransactionError(
                "Input Taproot leaf script key's control block size is not valid");

            bytevector script_v;
            s >> script_v;
            if (script_v.empty()) throw TransactionError("Input Taproot leaf script must be at least 1 byte");

            uint8_t leaf_ver = script_v.back();
            if (leaf_ver != 0x0C0) throw TransactionError("Input Taproot leaf script version is not 0xC0");
            script_v.pop_back();

            bytevector control_block(skey.remains());
            skey.read(control_block);
            if (!m_tap_scripts.emplace(CScript(script_v.begin(), script_v.end()), move(control_block)).second)
                throw TransactionError("Input Taproot leaf script already exist");

            break;
        }
        case PSBT_IN_TAP_BIP32_DERIVATION: {
            // throw std::runtime_error("Input Taproot bip32 derivation path is not supported by PSBT");
            if (!key_lookup.emplace(key).second) throw TransactionError(
                "Duplicate Key, input Taproot BIP32 keypath already provided");
            if (key.size() != 33) throw TransactionError("Input Taproot BIP32 keypath key is not at 33 bytes");

            xonly_pubkey pk;
            skey.read(pk);
            std::set<uint256> leaf_hashes;
            uint64_t value_len = ReadCompactSize(s);
            size_t before_hashes = s.size();
            s >> leaf_hashes;
            size_t after_hashes = s.size();
            size_t hashes_len = before_hashes - after_hashes;
            if (hashes_len > value_len) throw TransactionError("Input Taproot BIP32 keypath has an invalid length");

            size_t origin_len = value_len - hashes_len;
            m_tap_bip32_paths.emplace(move(pk), std::make_pair(move(leaf_hashes), DeserializeKeyOrigin(s, origin_len)));
            break;
        }
        case PSBT_IN_TAP_INTERNAL_KEY: {
            if (!key_lookup.emplace(key).second) throw TransactionError("Duplicate Key, input Taproot internal key already provided");
            if (key.size() != 1) throw TransactionError("Input Taproot internal key key is more than one byte type");

            m_tap_internal_key.emplace();
            s >> m_tap_internal_key->get_vector();
            break;
        }
        case PSBT_IN_TAP_MERKLE_ROOT: {
            if (!key_lookup.emplace(key).second) throw TransactionError("Duplicate Key, input Taproot merkle root already provided");
            if (key.size() != 1) throw TransactionError("Input Taproot merkle root key is more than one byte type");

            m_tap_merkle_root.emplace();
            DeserializeAsValue(s, *m_tap_merkle_root);
            break;
        }
        case PSBT_IN_PROPRIETARY: {
            PSBTProprietary this_prop;
            this_prop.identifier.resize(ReadCompactSize(skey));
            skey.read(this_prop.identifier);
            this_prop.subtype = ReadCompactSize(skey);
            this_prop.key = move(key);

            if (m_proprietary.contains(this_prop)) throw TransactionError(
                "Duplicate Key, proprietary key already found");

            s >> this_prop.value;
            m_proprietary.emplace(move(this_prop));
            break;
        }
        // Unknown stuff
        default: {
            if (unknown.contains(key)) throw TransactionError("Duplicate Key, key for unknown value already provided");

            // Read in the value
            bytevector val_bytes;
            s >> val_bytes;
            unknown.emplace(std::move(key), std::move(val_bytes));
            break;
        }
        }
    }

    if (!found_sep) throw TransactionError("Separator is missing at the end of an input map");
}


bool PSBTOutput::IsNull() const
{
    return !redeem_script && !witness_script && hd_keypaths.empty() && unknown.empty();
}

void PSBTOutput::Merge(const PSBTOutput& output)
{
    hd_keypaths.insert(output.hd_keypaths.begin(), output.hd_keypaths.end());
    unknown.insert(output.unknown.begin(), output.unknown.end());
    m_tap_bip32_paths.insert(output.m_tap_bip32_paths.begin(), output.m_tap_bip32_paths.end());

    if (!redeem_script && output.redeem_script)
        redeem_script = output.redeem_script;

    if (!witness_script && output.witness_script)
        witness_script = output.witness_script;

    if (!m_tap_internal_key && output.m_tap_internal_key)
        m_tap_internal_key = output.m_tap_internal_key;

    if (m_tap_tree.empty() && !output.m_tap_tree.empty())
        m_tap_tree = output.m_tap_tree;
}

void PSBTOutput::Serialize(DataStream &s) const
{
    if (redeem_script) {
        SerializeAsValue(s, CompactSizeWriter(PSBT_OUT_REDEEMSCRIPT));
        s << *redeem_script;
    }

    if (witness_script) {
        SerializeAsValue(s, CompactSizeWriter(PSBT_OUT_WITNESSSCRIPT));
        s << *witness_script;
    }

    SerializeHDKeypaths(s, hd_keypaths, CompactSizeWriter(PSBT_OUT_BIP32_DERIVATION));

    for (const auto &entry: m_proprietary) {
        s << entry.key;
        s << entry.value;
    }

    if (m_tap_internal_key) {
        SerializeAsValue(s, CompactSizeWriter(PSBT_OUT_TAP_INTERNAL_KEY));
        s << m_tap_internal_key->get_vector();
    }

    if (!m_tap_tree.empty()) {
        SerializeAsValue(s, CompactSizeWriter(PSBT_OUT_TAP_TREE));
        bytevector value;
        VectorWriter s_value{value, 0};
        for (const auto &[depth, leaf_ver, script]: m_tap_tree) {
            s_value << depth;
            s_value << leaf_ver;
            s_value << script;
        }
        s << value;
    }

    for (const auto &[pk, leaf]: m_tap_bip32_paths) {
        const auto &[leaf_hashes, origin] = leaf;
        SerializeAsValue(s, CompactSizeWriter(PSBT_OUT_TAP_BIP32_DERIVATION), Span(pk));
        bytevector value;
        VectorWriter s_value{value, 0};
        s_value << leaf_hashes;
        SerializeKeyOrigin(s_value, origin);
        s << value;
    }

    for (auto &entry: unknown) {
        s << entry.first;
        s << entry.second;
    }

    s << PSBT_SEPARATOR;
}

void PSBTOutput::Deserialize(DataStream& s)
{
    std::set<bytevector> key_lookup;

    // Read loop
    bool found_sep = false;
    while (!s.empty()) {
        // Read
        bytevector key;
        s >> key;

        // the key is empty if that was actually a separator byte
        // This is a special case for key lengths 0 as those are not allowed (except for separator)
        if (key.empty()) {
            found_sep = true;
            break;
        }

        auto skey = cex::make_stream(key);
        uint64_t type = ReadCompactSize(skey);

        switch (type) {
        case PSBT_OUT_REDEEMSCRIPT: {
            if (!key_lookup.emplace(key).second) throw TransactionError( "Duplicate Key, output redeemScript already provided");
            if (key.size() != 1) throw TransactionError("Output redeemScript key is more than one byte type");

            redeem_script.emplace();
            s >> *redeem_script;
            break;
        }
        case PSBT_OUT_WITNESSSCRIPT: {
            if (!key_lookup.emplace(key).second) throw TransactionError( "Duplicate Key, output witnessScript already provided");
            if (key.size() != 1) throw TransactionError("Output witnessScript key is more than one byte type");

            witness_script.emplace();
            s >> *witness_script;
            break;
        }
        case PSBT_OUT_BIP32_DERIVATION: {
            DeserializeHDKeypaths(s, key, hd_keypaths);
            break;
        }
        case PSBT_OUT_TAP_INTERNAL_KEY: {
            if (!key_lookup.emplace(key).second) throw TransactionError(
                "Duplicate Key, output Taproot internal key already provided");
            if (key.size() != 1) throw TransactionError("Output Taproot internal key key is more than one byte type");

            m_tap_internal_key.emplace();
            s >> m_tap_internal_key->get_vector();
            break;
        }
        case PSBT_OUT_TAP_TREE: {
            if (!key_lookup.emplace(key).second) throw TransactionError(
                "Duplicate Key, output Taproot tree already provided");
            if (key.size() != 1) throw TransactionError("Output Taproot tree key is more than one byte type");

            bytevector tree_v;
            s >> tree_v;
            SpanReader s_tree{tree_v};
            if (s_tree.empty()) throw TransactionError("Output Taproot tree must not be empty");

            //TaprootBuilder builder;
            while (!s_tree.empty()) {
                uint8_t depth;
                uint8_t leaf_ver;
                bytevector script;
                s_tree >> depth;
                s_tree >> leaf_ver;
                s_tree >> script;

                if (depth > TAPROOT_CONTROL_MAX_NODE_COUNT) throw TransactionError(
                    "Output Taproot tree has as leaf greater than Taproot maximum depth");
                if ((leaf_ver & ~TAPROOT_LEAF_MASK) != 0) throw TransactionError(
                    "Output Taproot tree has a leaf with an invalid leaf version");

                m_tap_tree.emplace_back(depth, leaf_ver, script);
            }
            break;
        }
        case PSBT_OUT_TAP_BIP32_DERIVATION: {
            if (!key_lookup.emplace(key).second) throw TransactionError(
                "Duplicate Key, output Taproot BIP32 keypath already provided");
            if (key.size() != 33) throw TransactionError("Output Taproot BIP32 keypath key is not at 33 bytes");

            xonly_pubkey pk(key.end() - 32, key.end());

            std::set<uint256> leaf_hashes;
            uint64_t value_len = ReadCompactSize(s);
            size_t before_hashes = s.size();
            s >> leaf_hashes;
            size_t after_hashes = s.size();
            size_t hashes_len = before_hashes - after_hashes;
            if (hashes_len > value_len) throw TransactionError("Output Taproot BIP32 keypath has an invalid length");

            size_t origin_len = value_len - hashes_len;
            m_tap_bip32_paths.emplace(move(pk), std::make_pair(move(leaf_hashes), DeserializeKeyOrigin(s, origin_len)));
            break;
        }
        case PSBT_OUT_PROPRIETARY: {
            PSBTProprietary this_prop;
            this_prop.identifier.resize(ReadCompactSize(skey));
            skey.read(this_prop.identifier);
            this_prop.subtype = ReadCompactSize(skey);
            this_prop.key = move(key);

            if (m_proprietary.contains(this_prop)) throw TransactionError( "Duplicate Key, proprietary key already found");

            s >> this_prop.value;
            m_proprietary.emplace(move(this_prop));
            break;
        }
        // Unknown stuff
        default: {
            if (unknown.contains(key)) throw TransactionError("Duplicate Key, key for unknown value already provided");

            // Read in the value
            bytevector val_bytes;
            s >> val_bytes;
            unknown.emplace(std::move(key), std::move(val_bytes));
            break;
        }
        }
    }
    if (!found_sep) throw TransactionError("Separator is missing at the end of an output map");
}


bool PSBTInputSigned(const PSBTInput& input)
{
    return input.final_script_sig || input.final_script_witness;
}

bool PSBTInputSignedAndVerified(const PSBT psbt, unsigned int input_index, const PrecomputedTransactionData* txdata)
{
    CTxOut utxo;
    assert(psbt.inputs.size() >= input_index);
    const PSBTInput& input = psbt.inputs[input_index];

    if (input.non_witness_utxo) {
        // If we're taking our information from a non-witness UTXO, verify that it matches the prevout.
        COutPoint prevout = psbt.base_tx->vin[input_index].prevout;
        if (prevout.n >= input.non_witness_utxo->vout.size()) {
            return false;
        }
        if (input.non_witness_utxo->GetHash() != prevout.hash) {
            return false;
        }
        utxo = input.non_witness_utxo->vout[prevout.n];
    } else if (input.witness_utxo) {
        utxo = *input.witness_utxo;
    } else {
        return false;
    }

    if (txdata) {
        return VerifyScript(input.final_script_sig.value_or(CScript()), utxo.scriptPubKey, input.final_script_witness ? &input.final_script_witness.value() : nullptr, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker{&(*psbt.base_tx), input_index, utxo.nValue, *txdata, MissingDataBehavior::FAIL});
    } else {
        return VerifyScript(input.final_script_sig.value_or(CScript()), utxo.scriptPubKey, input.final_script_witness ? &input.final_script_witness.value() : nullptr, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker{&(*psbt.base_tx), input_index, utxo.nValue, MissingDataBehavior::FAIL});
    }
}

size_t CountPSBTUnsignedInputs(const PSBT& psbt) {
    size_t count = 0;
    for (const auto& input : psbt.inputs) {
        if (!PSBTInputSigned(input)) {
            count++;
        }
    }

    return count;
}



}
