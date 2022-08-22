#pragma once

#include <vector>
#include <string>
#include <memory>
#include <regex>


#include "common.hpp"
#include "utils.hpp"


namespace l15::core {


class ChainApi {
public:
    typedef std::pair<std::string, std::string> string_pair_t;
private:
    static std::regex sNewlineRegExp;

    std::unique_ptr<const IBech32Coder> m_bech32;
    std::vector<std::string> m_default;
    const char* m_cli_path;
public:

    template <typename T>
    static void Log(const T&);

    template<class B32>
    ChainApi(B32 , std::vector<std::string> &&default_opts, const char *cli_path = "bitcoin-cli")
        : m_bech32(new B32()), m_default(default_opts), m_cli_path(cli_path) { }
    ~ChainApi() = default;


    std::string Bech32Encode(const xonly_pubkey& pk) const
    { return m_bech32->Encode(pk); }
    xonly_pubkey Bech32Decode(const std::string& address) const
    { return m_bech32->Decode(address); };

    void StopNode() const;

    void CreateWallet(std::string&& name) const;

    void CheckConnection() const;
    std::string SendToAddress(const std::string& address, const std::string& amount) const;
    std::string GetTxOut(const std::string& txidhex, const std::string& out) const;
    uint32_t GetChainHeight() const;
    std::string GetNewAddress(const std::string& label = "", const std::string& address_type = "bech32m") const;
    std::string GenerateToAddress(const std::string& address, const std::string &nblocks) const;

    // locktime < 500 000 000 - means lock time in block height
    // locktime >= 500 000 000 - means UNIX timestamp
//    transaction_ptr CreateSegwitTx(const CScript &script,
//                               const string_pair_t& utxo, const std::vector<string_pair_t>& outs_addr_amount,
//                               uint32_t locktime = 0) const;

    std::string SpendSegwitTx(CMutableTransaction &tx, const std::vector<bytevector>& witness_stack) const;
    std::string SpendTx(const CTransaction &tx) const;
    std::string TestTxSequence(const std::vector<CMutableTransaction> &txs) const;

    std::string GetBlock(const std::string& block_hash, const std::string& verbosity = "2");

    std::tuple<COutPoint, CTxOut> CheckOutput(const string& txid, const string& address) const;
};

}

