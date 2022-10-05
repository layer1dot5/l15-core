
#include <string>
#include <vector>
#include <sstream>


#include "CLI11.hpp"
#include "common.hpp"
#include "channel_keys.hpp"
#include "wallet_api.hpp"
#include "signer_api.hpp"
#include "signer_service.hpp"
#include "util/strencodings.h"
#include "zmq_service.hpp"
#include "generic_service.hpp"

using namespace l15;
using namespace l15::core;

const char * const CONF = "--config";
const char * const SKEY = "--seckey,-s";
const char * const LISTEN_ADDR = "--listen-addr,-l";
const char * const PEER_ADDR = "--peer,-p";
const char * const INPUT = "--input,-i";
const char * const VERBOSE = "--verbose,-v";
const char * const DRYRUN = "--dry-run,-d";



class SignerConfig
{
private:
    CLI::App mApp;

public:
    SignerConfig();
    ~SignerConfig() = default;

    size_t mVerbose;
    bool mDryRun;
    std::string mSecKey;
    std::string mListenAddress;
    l15::ZmqService p2pService;
    l15::service::GenericService mBgService;
    std::string mInput;
    CLI::Option* mHelp;

    void ProcessConfig(int argc, const char *const argv[])
    {
        try {
            mApp.parse(argc, argv);
        }
        catch (const CLI::ParseError &e) {
            mApp.exit(e);
        }
    }

    void Print() const {
        std::clog << "seckey: " << mSecKey << "\n";
        std::clog << "listen-addr: " << mListenAddress << "\n";
//        for (const auto& addr: mPeerAddresses) {
//            std::clog << "peer-addr: " << addr << "\n";
//        }
        std::clog << std::endl;
    }

};


SignerConfig::SignerConfig()
: mApp("Tool to generate threshold signature", "signer")
, mBgService(10)
{
    mApp.set_config(CONF, "signer.conf", "Read the configuration file");
    mApp.set_version_flag("--version", "signer tool version: 0");
    mHelp = mApp.set_help_flag("--help,-h");

    mApp.add_flag(VERBOSE, mVerbose, "Log more traces including configuration, -vv forces to print all the peer from configuration");

    mApp.add_flag(DRYRUN, mDryRun, "Does not run signer service, just checks config and prints its output");

    mApp.add_option(SKEY,
                    mSecKey,
                    "Secret key, default random")->configurable(true);

    mApp.add_option(LISTEN_ADDR,
                    mListenAddress,
                    "Address to listen")->configurable(true);

    mApp.add_option_function<std::string>(PEER_ADDR, [&](const std::string& peer)
    {
        if (peer.length() < 70 || peer[peer.length() - 65] != '|') {
            std::cerr << "Wrong peer configuration: " << peer << std::endl;
            throw CLI::ValidationError(PEER_ADDR, "Wrong peer: " + peer);
        }

        auto pk = ParseHex(peer.substr(peer.length() - 64));
        auto addr = peer.substr(0, peer.length() - 65);

        p2pService.AddPeer(move(pk), move(addr));
    },
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

    if (bool(*config.mHelp)) exit(0);
    if (config.mVerbose) config.Print();

    WalletApi wallet;
    seckey sk;

    if (!config.mSecKey.empty()) {
        sk = ParseHex(config.mSecKey);
    }

    size_t N = config.p2pService.GetPeersMap().size() + 1;
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

    signer->SetPublisher([&config](const p2p::Message& m) { config.p2pService.Publish(m); });

    size_t i = 0;
    for (const auto& peer: config.p2pService.GetPeersMap()) {

        signer->AddPeer(xonly_pubkey(peer.first), [&](const p2p::Message m)
        {
            config.p2pService.Send(peer.first, m);
        });

        if (config.mVerbose == 2) {
            std::clog << "\nPeer:    " << HexStr(peer.first) << "\n";
            std::clog << "Address: " << peer.second << std::endl;
        }
    }

    if (config.mDryRun || *config.mHelp) {
        exit(0);
    }

    config.p2pService.BindAddress(config.mListenAddress, [&signer](const p2p::Message& m){ signer->Accept(m); });

    signer_service::SignerService signerService(config.mBgService);
    signerService.AddSigner(signer);

    auto aggKeyFuture = signerService.NegotiateKey(signer->GetLocalPubKey());
    xonly_pubkey shared_pk = aggKeyFuture.get();

    auto nonceFuture = signerService.PublishNonces(signer->GetLocalPubKey(), 2);
    nonceFuture.wait();

    uint256 message;
    CSHA256().Write((unsigned char*)config.mInput.data(), config.mInput.length()).Finalize(message.data());

    auto signFuture = signerService.Sign(signer->GetLocalPubKey(), message);
    signature sig = signFuture.get();

    std::cout << HexStr(sig) << std::endl;

}
