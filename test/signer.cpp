
#include "CLI11.hpp"
#include "common.hpp"
#include "channel_keys.hpp"
#include "wallet_api.hpp"
#include "signer_api.hpp"
#include "p2p_service.hpp"
#include "signer_service.hpp"
#include "util/strencodings.h"

using namespace l15;
using namespace l15::core;

const char * const CONF = "--config";
const char * const SKEY = "--seckey,-s";
const char * const LISTEN_ADDR = "--listen-addr,-l";
const char * const PEER_ADDR = "--peer,-p";
const char * const INPUT = "--input,-i";
const char * const VERBOSE = "--verbose,-v";


class SignerConfig
{
private:
    CLI::App mApp;

public:
    SignerConfig();
    ~SignerConfig() = default;

    bool mVerbose;
    std::string mSecKey;
    std::string mListenAddress;
    stringvector mPeerAddresses;
    std::string mInput;

    void ProcessConfig(int argc, const char *const argv[])
    {
        try {
            mApp.parse(argc, argv);
        }
        catch (const CLI::ParseError &e) {
            mApp.exit(e);
        }
    }

    void Print() {
        std::clog << "seckey: " << mSecKey << "\n";
        std::clog << "listen-addr: " << mListenAddress << "\n";
        for (const auto& addr: mPeerAddresses) {
            std::clog << "peer-addr: " << addr << "\n";
        }
        std::clog << std::endl;
    }
};

SignerConfig::SignerConfig() : mApp("Tool to generate threshold signature", "signer")
{
    mApp.set_config(CONF, "signer.conf", "Read the configuration file");
    mApp.set_version_flag("--version", "signer tool version: 0");
    mApp.set_help_flag("--help,-h");

    mApp.add_flag(VERBOSE, mVerbose, "Log more traces including configuration");

    mApp.add_option(SKEY,
                    mSecKey,
                    "Secret key, default random")->configurable(true);

    mApp.add_option(LISTEN_ADDR,
                    mListenAddress,
                    "Address to listen")->configurable(true);

    mApp.add_option(PEER_ADDR,
                    mPeerAddresses,
                    "Signing counterparty peer address")->configurable(true)->take_all();

    mApp.add_option(INPUT,
                    mInput,
                    "Input message to sign")->configurable(true);
}

new_sigop_handler new_sigop_hdl = [](SignerApi&, operation_id) { };
aggregate_sig_handler sig_hdl = [](SignerApi&, operation_id) { };
error_handler error_hdl = [](Error&& e) { std::cerr << "Fatal error: " << e.what(); exit(1); };

general_handler key_hdl = [](SignerApi& s)
{
    s.AggregateKey();
    s.CommitNonces(2);
};

int main(int argc, char* argv[])
{
    SignerConfig config;
    config.ProcessConfig(argc, argv);

    if (config.mVerbose) config.Print();

    WalletApi wallet;
    seckey sk;

    if (!config.mSecKey.empty()) {
        sk = ParseHex(config.mSecKey);
    }

    size_t N = config.mPeerAddresses.size() + 1;
    size_t K = (N%2) ? (N+1)/2 : N/2;

    std::shared_ptr<SignerApi> signer = make_shared<SignerApi>(
                     config.mSecKey.empty()
                         ? l15::core::ChannelKeys(wallet.Secp256k1Context())
                         : l15::core::ChannelKeys(wallet.Secp256k1Context(), std::move(sk)),
                     N, K,
                     new_sigop_hdl, sig_hdl, error_hdl);

    if (config.mVerbose) {
        std::clog << "sk: " << HexStr(signer->GetSecKey()) << "\n";
        std::clog << "pk: " << HexStr(signer->GetLocalPubKey()) << std::endl;
    }

    service::GenericService bgservice;
    p2p_service::P2PService p2pService(config.mListenAddress, [&signer](const p2p::Message& m){signer->Accept(m);});

    size_t i = 0;
    for (const auto& addr: config.mPeerAddresses) {
        //signer->AddPeer(i++, p2pService.GetLink(addr));
    }

    signer_service::SignerService signerService;
    auto aggKeyFuture = signerService.NegotiateKey(signer);
    xonly_pubkey shred_pk = aggKeyFuture.get();

    auto nonceFuture = signerService.MakeNonces(signer->GetLocalPubKey(), 2);
    nonceFuture.wait();

    uint256 message;
    CSHA256().Write((unsigned char*)config.mInput.data(), config.mInput.length()).Finalize(message.data());

    auto signFuture = signerService.Sign(signer->GetLocalPubKey(), message);
    signature sig = signFuture.get();

    std::cout << HexStr(sig) << std::endl;

}
