// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "psbt.hpp"

#include "policy/policy.h"
// #include "script/signingprovider.h"
// #include <util/check.h>
#include <deque>
#include <wrapstream.hpp>

#include "util/strencodings.h"
#include "base64.hpp"

namespace l15::core {

PartiallySignedTransaction::PartiallySignedTransaction(const CMutableTransaction& tx) : tx(tx)
{
    inputs.resize(tx.vin.size());
    outputs.resize(tx.vout.size());
}

bool PartiallySignedTransaction::IsNull() const
{
    return !tx && inputs.empty() && outputs.empty() && unknown.empty();
}

bool PartiallySignedTransaction::Merge(const PartiallySignedTransaction& psbt)
{
    // Prohibited to merge two PSBTs over different transactions
    if (tx->GetHash() != psbt.tx->GetHash()) {
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

bool PartiallySignedTransaction::AddInput(const CTxIn& txin, PSBTInput& psbtin)
{
    if (std::find(tx->vin.begin(), tx->vin.end(), txin) != tx->vin.end()) {
        return false;
    }
    tx->vin.push_back(txin);
    psbtin.partial_sigs.clear();
    psbtin.final_script_sig.reset();
    psbtin.final_script_witness.reset();
    inputs.push_back(psbtin);
    return true;
}

bool PartiallySignedTransaction::AddOutput(const CTxOut& txout, const PSBTOutput& psbtout)
{
    tx->vout.push_back(txout);
    outputs.push_back(psbtout);
    return true;
}

bool PartiallySignedTransaction::GetInputUTXO(CTxOut& utxo, int input_index) const
{
    const PSBTInput& input = inputs[input_index];
    uint32_t prevout_index = tx->vin[input_index].prevout.n;
    if (input.non_witness_utxo) {
        if (prevout_index >= input.non_witness_utxo->vout.size()) {
            return false;
        }
        if (input.non_witness_utxo->GetHash() != tx->vin[input_index].prevout.hash) {
            return false;
        }
        utxo = input.non_witness_utxo->vout[prevout_index];
    } else if (input.witness_utxo) {
        utxo = *input.witness_utxo;
    } else {
        return false;
    }
    return true;
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

bool PSBTInputSigned(const PSBTInput& input)
{
    return input.final_script_sig || input.final_script_witness;
}

bool PSBTInputSignedAndVerified(const PartiallySignedTransaction psbt, unsigned int input_index, const PrecomputedTransactionData* txdata)
{
    CTxOut utxo;
    assert(psbt.inputs.size() >= input_index);
    const PSBTInput& input = psbt.inputs[input_index];

    if (input.non_witness_utxo) {
        // If we're taking our information from a non-witness UTXO, verify that it matches the prevout.
        COutPoint prevout = psbt.tx->vin[input_index].prevout;
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
        return VerifyScript(input.final_script_sig.value_or(CScript()), utxo.scriptPubKey, input.final_script_witness ? &input.final_script_witness.value() : nullptr, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker{&(*psbt.tx), input_index, utxo.nValue, *txdata, MissingDataBehavior::FAIL});
    } else {
        return VerifyScript(input.final_script_sig.value_or(CScript()), utxo.scriptPubKey, input.final_script_witness ? &input.final_script_witness.value() : nullptr, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker{&(*psbt.tx), input_index, utxo.nValue, MissingDataBehavior::FAIL});
    }
}

size_t CountPSBTUnsignedInputs(const PartiallySignedTransaction& psbt) {
    size_t count = 0;
    for (const auto& input : psbt.inputs) {
        if (!PSBTInputSigned(input)) {
            count++;
        }
    }

    return count;
}


// PartiallySignedTransaction DecodeBase64PSBT(const std::string_view& base64_tx)
// {
//     try {
//         auto tx_data = base64::decode<std::deque<uint8_t>>(base64_tx);
//         return PartiallySignedTransaction(tx_data);
//     }
//     catch(std::exception& ) {
//         std::throw_with_nested(TransactionError("decode PSBT"));
//     }
// }


}
