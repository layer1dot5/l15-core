#pragma once

#include <vector>
#include <string>
#include <regex>


#include "common.hpp"
#include "utils.hpp"
#include "exechelper.hpp"


namespace l15::core {


class ChainApi {
public:
    typedef std::pair<std::string, std::string> string_pair_t;
private:
    static std::regex sNewlineRegExp;

    std::vector<std::string> m_default;
    std::string m_cli_path;
public:
    ChainApi(std::vector<std::string> &&default_opts, const std::string& cli_path = "bitcoin-cli")
        : m_default(default_opts), m_cli_path(cli_path) { }
    ~ChainApi() = default;

    void StopNode() const;

    template <typename ... ARGS>
    std::string Call(ARGS&&... args) const
    {
        ExecHelper exec(m_cli_path, false);
        for (const std::string& v: m_default) { exec.Arguments().emplace_back(v); }
        ([&]<typename T>(T&& arg){exec.Arguments().emplace_back(std::forward<T>(arg));}(std::forward<decltype(args)>(args)), ...);

        return exec.Run();
    }

    void CreateWallet(std::string name) const;
    std::string GetWalletInfo() const;
    void WalletPassPhrase(std::string phrase, std::string lifetime) const;

    void CheckConnection() const { GetChainHeight(); }
    std::string SendToAddress(std::string address, std::string amount) const;
    std::string GetTxOut(std::string txidhex, std::string out) const;
    uint32_t GetChainHeight() const;
    std::string GetNewAddress(std::string label = "", std::string address_type = "bech32m") const;
    std::string GenerateToAddress(std::string address, std::string nblocks) const;

    // locktime < 500 000 000 - means lock time in block height
    // locktime >= 500 000 000 - means UNIX timestamp
//    transaction_ptr CreateSegwitTx(const CScript &script,
//                               const string_pair_t& utxo, const std::vector<string_pair_t>& outs_addr_amount,
//                               uint32_t locktime = 0) const;

    std::string SpendSegwitTx(CMutableTransaction &tx, const std::vector<bytevector>& witness_stack) const;
    std::string SpendTx(const CTransaction &tx) const;
    CTransaction GetTx(std::string txid) const;
    std::string TestTxSequence(const std::vector<CMutableTransaction> &txs) const;

    std::string GetBlock(string block_hash, string verbosity = "2") const;
    std::string GetZMQNotifications() const;

    std::tuple<COutPoint, CTxOut> CheckOutput(const string& txid, const string& address) const;

    std::string EstimateSmartFee(std::string confirmation_target, std::string mode = "CONSERVATIVE") const;
};

}

