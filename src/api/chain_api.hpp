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

    std::vector<std::string> m_default;
    const char* m_cli_path;
public:

    template <typename T>
    static void Log(const T&);

    ChainApi(std::vector<std::string> &&default_opts, const char *cli_path = "bitcoin-cli")
        : m_default(default_opts), m_cli_path(cli_path) { }
    ~ChainApi() = default;



    void StopNode() const;

    void CreateWallet(std::string&& name) const;
    std::string GetWalletInfo() const;
    void WalletPassPhrase(const std::string& phrase, const std::string& lifetime) const;

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

    std::string GetBlock(const std::string& block_hash, const std::string& verbosity = "2") const;
    std::string GetZMQNotifications() const;

    std::tuple<COutPoint, CTxOut> CheckOutput(const string& txid, const string& address) const;

    std::string EstimateSmartFee(const std::string& confirmation_target, const std::string& mode = "CONSERVATIVE") const;
};

}

