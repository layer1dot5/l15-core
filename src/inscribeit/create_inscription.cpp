
#include <ranges>

#include "version.h"
#include "serialize.h"

#include "create_inscription.hpp"
#include "utils.hpp"
#include "script_merkle_tree.hpp"
#include "channel_keys.hpp"


namespace l15::inscribeit {

namespace {

const size_t chunk_size = 520;
const bytevector ord_tag {'o', 'r', 'd'};
const bytevector one_tag {'\1'};

const size_t funding_tx_size = 150;
const size_t genesys_tx_size_base = 160;

CScript MakeInscriptionScript(const xonly_pubkey& pk, const std::string& content_type, const bytevector& data) {
    size_t chunks = data.size() / chunk_size;

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

CAmount CalculateOutputAmount(CAmount input_amount, CAmount fee_rate, size_t size)
{
    return input_amount - size * fee_rate / 1024;
}


}

CreateInscriptionBuilder::CreateInscriptionBuilder(const std::string& chain_mode)
{
    if (chain_mode == "mainnet") {
        m_bech_coder = std::make_unique<Bech32Coder<IBech32Coder::ChainType::BTC, IBech32Coder::ChainMode::MAINNET>>();
    }
    else if (chain_mode == "testnet") {
        m_bech_coder = std::make_unique<Bech32Coder<IBech32Coder::ChainType::BTC, IBech32Coder::ChainMode::TESTNET>>();
    }
    else if (chain_mode == "regtest") {
        m_bech_coder = std::make_unique<Bech32Coder<IBech32Coder::ChainType::BTC, IBech32Coder::ChainMode::REGTEST>>();
    }
    else {
        throw std::invalid_argument(chain_mode);
    }
}

CreateInscriptionBuilder &l15::inscribeit::CreateInscriptionBuilder::UTXO(const string &txid, uint32_t nout, const std::string amount)
{
    m_txid = txid;
    m_nout = nout;
    m_amount = ParseAmount(amount);
    return *this;
}

CreateInscriptionBuilder &CreateInscriptionBuilder::FeeRate(const string &rate)
{
    m_fee_rate = ParseAmount(rate);
    return *this;
}

CreateInscriptionBuilder &CreateInscriptionBuilder::Data(const std::string& content_type, const string &hex_data)
{
    m_content_type = content_type;
    m_data = unhex<bytevector>(hex_data);
    return *this;
}

CreateInscriptionBuilder &CreateInscriptionBuilder::DestinationAddress(const string &addr)
{
    m_destination_pk = m_bech_coder->Decode(addr);
    return *this;
}

CreateInscriptionBuilder &CreateInscriptionBuilder::DestinationPK(const string &pubkey)
{
    m_destination_pk = unhex<xonly_pubkey>(pubkey);
    return *this;
}

CreateInscriptionBuilder &CreateInscriptionBuilder::PrivKeys(const std::string& utxo_sk, const std::string& funding_sk, const std::string& genesys_sk)
{
    m_utxo_sk = unhex<seckey>(utxo_sk);
    m_funding_sk = unhex<seckey>(funding_sk);
    m_genesys_sk = unhex<seckey>(genesys_sk);
    return *this;
}

//CreateInscriptionBuilder &CreateInscriptionBuilder::Signatures(const string &funding_sig, const string &genesys_sig)
//{
//    m_funding_sig = unhex<signature>(funding_sig);
//    m_genesys_sig = unhex<signature>(genesys_sig);
//    return *this;
//}

std::vector<std::string> CreateInscriptionBuilder::MakeRawTransactions()
{
    if (m_genesys_sk) {
        core::ChannelKeys genesys_key(*m_genesys_sk);
        if (m_destination_pk) {
            if (genesys_key.GetLocalPubKey() != *m_destination_pk) {
                throw std::invalid_argument("destination pk does not match sk");
            }
        }
        else {
            m_destination_pk = genesys_key.GetLocalPubKey();
        }
    }

    if (m_utxo_sk) {
        core::ChannelKeys utxo_key(*m_utxo_sk);
        if (m_utxo_pk) {
            if (utxo_key.GetLocalPubKey() != *m_utxo_pk) {
                throw std::invalid_argument("UTXO pk does not match sk");
            }
        }
        else {
            m_utxo_pk = utxo_key.GetLocalPubKey();
        }
    }
    else if (!m_utxo_pk) {
        throw std::invalid_argument("No UTXO key is provided");
    }

    ScriptMerkleTree tap_tree(TreeBalanceType::WEIGHTED, {MakeInscriptionScript(m_destination_pk.value(), m_content_type, m_data)});
    uint256 root = tap_tree.CalculateRoot();

    xonly_pubkey funding_taproot_pk;
    uint8_t funding_taproot_parity;

    if (m_funding_sk) {
        core::ChannelKeys funding_key(*m_funding_sk);
        std::tie(funding_taproot_pk, funding_taproot_parity) = funding_key.AddTapTweak(root);
        if (m_funding_pk) {
            if (funding_taproot_pk != *m_funding_pk) {
                throw std::invalid_argument("Funding pk does not match sk");
            }
        }
        else {
            m_funding_pk = funding_taproot_pk;
        }
    }
    else if (!m_funding_pk) {
        throw std::invalid_argument("No funding key is provided");
    }

    CScript funding_pubkeyscript;
    funding_pubkeyscript << 1;
    funding_pubkeyscript << *m_funding_pk;

    CMutableTransaction funding_tx;
    funding_tx.vin = {CTxIn(COutPoint(uint256S(m_txid), m_nout))};
    funding_tx.vout = {CTxOut(m_amount, funding_pubkeyscript)};
//    funding_tx.vin.front().scriptWitness.stack.emplace_back(static_cast<bytevector>(signature()));
//
//    size_t funding_tx_size = GetSerializeSize(funding_tx, PROTOCOL_VERSION);
//
//    funding_tx.vout.front().nValue = CalculateOutputAmount(m_amount, m_fee_rate, funding_tx_size)



















    return std::vector<std::string>();
}



}