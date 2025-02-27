// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "common.hpp"
#include "utils.hpp"

#include "primitives/transaction.h"
#include "script/keyorigin.h"
#include "streams.h"

namespace l15::core {


/** A structure for PSBT proprietary types */
struct PSBTProprietary
{
    uint64_t subtype;
    bytevector identifier;
    bytevector key;
    bytevector value;

    bool operator<(const PSBTProprietary &b) const {
        return key < b.key;
    }
    bool operator==(const PSBTProprietary &b) const {
        return key == b.key;
    }
};

/** A structure for PSBTs which contain per-input information */
struct PSBTInput
{
    CTransactionRef non_witness_utxo;
    std::optional<CTxOut> witness_utxo;
    std::optional<CScript> redeem_script;
    std::optional<CScript> witness_script;
    std::optional<CScript> final_script_sig;
    std::optional<CScriptWitness> final_script_witness;
    std::map<compressed_pubkey, KeyOriginInfo> hd_keypaths;
    std::map<bytevector, std::pair<compressed_pubkey, bytevector>> partial_sigs;
    std::map<uint160, bytevector> ripemd160_preimages;
    std::map<uint256, bytevector> sha256_preimages;
    std::map<uint160, bytevector> hash160_preimages;
    std::map<uint256, bytevector> hash256_preimages;

    // Taproot fields
    std::optional<signature> m_tap_key_sig;
    std::map<std::pair<xonly_pubkey, uint256>, signature> m_tap_script_sigs;
    std::map<CScript, bytevector> m_tap_scripts; // tapscript -> control block
    std::map<xonly_pubkey, std::pair<std::set<uint256>, KeyOriginInfo>> m_tap_bip32_paths;
    std::optional<xonly_pubkey> m_tap_internal_key;
    std::optional<uint256> m_tap_merkle_root;

    std::map<bytevector, bytevector> unknown;
    std::set<PSBTProprietary> m_proprietary;
    std::optional<int> sighash_type;

    PSBTInput()= default;
    explicit PSBTInput(DataStream& s) {
        Deserialize(s);
    }

    bool IsNull() const;
    //void FillSignatureData(SignatureData& sigdata) const;
    //void FromSignatureData(const SignatureData& sigdata);
    void Merge(const PSBTInput& input);

    void Serialize(DataStream& s) const;
    void Deserialize(DataStream& s);
};

/** A structure for PSBTs which contains per output information */
struct PSBTOutput
{
    std::optional<CScript> redeem_script;
    std::optional<CScript> witness_script;
    std::map<compressed_pubkey, KeyOriginInfo> hd_keypaths;
    std::optional<xonly_pubkey> m_tap_internal_key;
    std::vector<std::tuple<uint8_t, uint8_t, bytevector>> m_tap_tree;
    std::map<xonly_pubkey, std::pair<std::set<uint256>, KeyOriginInfo>> m_tap_bip32_paths;
    std::map<bytevector, bytevector> unknown;
    std::set<PSBTProprietary> m_proprietary;

    PSBTOutput() = default;
    explicit PSBTOutput(DataStream& s) {
        Deserialize(s);
    }

    bool IsNull() const;
    // void FillSignatureData(SignatureData& sigdata) const;
    // void FromSignatureData(const SignatureData& sigdata);
    void Merge(const PSBTOutput& output);

    void Serialize(DataStream& s) const;
    void Deserialize(DataStream& s);
};

/** A version of CTransaction with the PSBT format*/
struct PSBT
{
    std::optional<CMutableTransaction> base_tx;
    // We use a vector of CExtPubKey in the event that there happens to be the same KeyOriginInfos for different CExtPubKeys
    // Note that this map swaps the key and values from the serialization
    //std::map<KeyOriginInfo, std::set<CExtPubKey>> m_xpubs;
    std::vector<PSBTInput> inputs;
    std::vector<PSBTOutput> outputs;
    std::map<bytevector, bytevector> unknown;
    uint32_t m_version = 0;
    std::optional<uint32_t> m_fallback_locktime;
    std::set<PSBTProprietary> m_proprietary;

    PSBT() = default;
    explicit PSBT(const CMutableTransaction& tx);
    explicit PSBT(const auto& s) {
        Deserialize(s);
    }

    bool IsNull() const;
    uint32_t GetVersion() const { return m_version; }

    /** Merge psbt into this. The two psbts must have the same underlying CTransaction (i.e. the
      * same actual Bitcoin transaction.) Returns true if the merge succeeded, false otherwise. */
    [[nodiscard]] bool Merge(const PSBT& psbt);
    bool AddInput(const CTxIn& txin, PSBTInput& psbtin);
    bool AddOutput(const CTxOut& txout, const PSBTOutput& psbtout);
    /**
     * Finds the UTXO for a given input index
     *
     * @param[out] utxo The UTXO of the input if found
     * @param[in] input_index Index of the input to retrieve the UTXO of
     * @return Whether the UTXO for the specified input was found
     */
    const CTxOut& GetInputUTXO(size_t input_index) const;

    void Serialize(DataStream& s) const;

    template<typename Container>
    Container Serialize() const
    {
        DataStream s;
        Serialize(s);
        Container res;
        std::ranges::transform(s, cex::smartinserter(res, res.end()), [](const auto& v) { return static_cast<typename Container::value_type>(v); });
        return res;
    }

    void Deserialize(DataStream& s);

    template<typename Container, typename = std::enable_if_t<!std::is_same_v<std::remove_cv_t<Container>, DataStream>, Container>>
    void Deserialize(const Container& raw_data)
    {
        DataStream s(raw_data);
        Deserialize(s);
    }
};


/** Compute a PrecomputedTransactionData object from a psbt. */
PrecomputedTransactionData PrecomputePSBTData(const PSBT& psbt);

/** Checks whether a PSBTInput is already signed by checking for non-null finalized fields. */
bool PSBTInputSigned(const PSBTInput& input);

/** Checks whether a PSBTInput is already signed by doing script verification using final fields. */
bool PSBTInputSignedAndVerified(const PSBT psbt, unsigned int input_index, const PrecomputedTransactionData* txdata);


/** Counts the unsigned inputs of a PSBT. */
size_t CountPSBTUnsignedInputs(const PSBT& psbt);


}

