#pragma once

#include <vector>
#include <string>
#include <memory>
#include <regex>

#include "script/script.h"
#include "common.hpp"

#include "common_api.hpp"


namespace l15::api {

class WalletApi;

class ChainApi {
public:
    typedef std::pair<std::string, std::string> string_pair_t;
private:
    static std::regex sNewlineRegExp;

    WalletApi& m_wallet;
    std::vector<std::string> m_default;
    const char* m_cli_path;
    const char* m_daemon_path;
public:

    template <typename T>
    static void Log(const T&);

    ChainApi(WalletApi &wallet, std::vector<std::string> &&default_opts, const char *cli_path = "bitcoin-cli", const char* daemon_path = "bitcoind")
        : m_wallet(wallet), m_default(default_opts), m_cli_path(cli_path), m_daemon_path(daemon_path) {}
    ~ChainApi() = default;

    const WalletApi& Wallet() const {
        return m_wallet;
    }

    void StopNode() const;

    void CreateWallet(std::string&& name) const;

    void CheckConnection() const;
    std::string SendToAddress(const std::string& address, const std::string& amount) const;
    std::string GetTxOut(const std::string& txidhex, const std::string& out) const;
    uint32_t GetChainHeight() const;
    std::string GetNewAddress(const std::string& label = "", const std::string& address_type = "bech32") const;
    std::string GenerateToOwnAddress(const std::string &nblocks) const;

    // locktime < 500 000 000 - means lock time in block height
    // locktime >= 500 000 000 - means UNIX timestamp
    transaction_ptr CreateSegwitTx(const CScript &script,
                               const string_pair_t& utxo, const std::vector<string_pair_t>& outs_addr_amount,
                               uint32_t locktime = 0) const;

    std::string SpendSegwitTx(CMutableTransaction &tx, const std::vector<bytevector>& witness_stack) const;
    std::string SpendTx(const CTransaction &tx) const;
    std::string TestTxSequence(const std::vector<CMutableTransaction> &txs) const;
};

}

