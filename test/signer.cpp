
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
#include "generic_service.hpp"
#include "zmq_service.hpp"

using namespace l15;
using namespace l15::core;

const char * const CONF = "--config";
const char * const SKEY = "--seckey,-k";
const char * const LISTEN_ADDR = "--listen-addr,-l";
const char * const PEER_ADDR = "--peer,-p";
const char * const INPUT = "--input,-i";
const char * const VERBOSE = "--verbose,-v";
const char * const DRYRUN = "--dry-run,-d";
const char * const DOSIGN = "--sign,-s";



class Signer
{
    CLI::App mApp;

public:
    size_t mVerbose;
    bool mDryRun;
    bool mDoSign;
    std::string mSecKey;
    std::string mListenAddress;
    std::shared_ptr<l15::service::GenericService> mTaskService;
    WalletApi mWallet;
    l15::ZmqService mPeerService;
    std::string mInput;
    CLI::Option* mHelp;

    Signer();
    ~Signer() = default;

    void ProcessConfig(int argc, const char *const argv[])
    {
        try {
            mApp.parse(argc, argv);
        }
        catch (const CLI::ParseError &e) {
            std::cerr << "Configuretion error: " << e.what() << std::endl;
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


Signer::Signer()
: mApp("Tool to generate threshold signature", "signer")
, mVerbose(0), mDryRun(false), mDoSign(false)
, mTaskService(std::make_shared<service::GenericService>(16))
, mWallet()
, mPeerService(mWallet.Secp256k1Context(), mTaskService)
{
    mApp.set_config(CONF, "signer.conf", "Read the configuration file");
    mApp.set_version_flag("--version", "signer tool version: 0");
    mHelp = mApp.set_help_flag("--help,-h");

    mApp.add_flag(VERBOSE, mVerbose, "Log more traces including configuration, -vv forces to print all the peer from configuration");

    mApp.add_flag(DRYRUN, mDryRun, "Does not run signer service, just checks config and prints its output");

    mApp.add_flag(DOSIGN, mDoSign, "Indicates does the peed participate in signature creation");

    mApp.add_option(SKEY,
                    mSecKey,
                    "Secret key, default random")->configurable(true);

    mApp.add_option(LISTEN_ADDR,
                    mListenAddress,
                    "Address to listen")->configurable(true);

    mApp.add_option_function<std::vector<std::string>>(PEER_ADDR, [&](const std::vector<std::string>& peers)
    {
        for(const auto& peer: peers) {
            if (peer.length() < 70 || peer[peer.length() - 65] != '|') {
                std::cerr << "Wrong peer configuration: " << peer << std::endl;
                throw CLI::ValidationError(PEER_ADDR, "Wrong peer: " + peer);
            }

            auto pk = ParseHex(peer.substr(peer.length() - 64));
            auto addr = peer.substr(0, peer.length() - 65);

            mPeerService.AddPeer(move(pk), move(addr));
        }
    },
    "Signing counterparty peer address")->configurable(true)->take_all();

    mApp.add_option(INPUT,
                    mInput,
                    "Input message to sign")->configurable(true);
}

error_handler error_hdl = [](Error&& e) { std::cerr << "Fatal error: " << e.what(); exit(1); };

int main(int argc, char* argv[])
{
    Signer config;
    config.ProcessConfig(argc, argv);

    if (bool(*config.mHelp)) exit(0);
    if (config.mVerbose) config.Print();

    seckey sk;

    if (!config.mSecKey.empty()) {
        sk = ParseHex(config.mSecKey);
    }

    size_t N = config.mPeerService.GetPeersMap().size();
    size_t K = (N%2) ? (N+1)/2 : N/2;

    std::shared_ptr<SignerApi> signer = make_shared<SignerApi>(
                     config.mSecKey.empty()
                         ? l15::core::ChannelKeys(config.mWallet.Secp256k1Context())
                         : l15::core::ChannelKeys(config.mWallet.Secp256k1Context(), std::move(sk)),
                     N, K,
                     error_hdl);

    if (config.mVerbose) {
        std::clog << "sk: " << HexStr(signer->GetSecKey()) << "\n";
        std::clog << "pk: " << HexStr(signer->GetLocalPubKey()) << std::endl;
    }

    signer->SetPublisher([&config](const p2p::FrostMessage& m) { config.mPeerService.Publish(m); });

    for (const auto& peer: config.mPeerService.GetPeersMap()) {

        signer->AddPeer(xonly_pubkey(peer.first), [&](const p2p::FrostMessage& m)
        {
            config.mPeerService.Send(peer.first, m);
        });

        if (config.mVerbose == 2) {
            std::clog << "\nPeer:    " << hex(peer.first) << "\n";
            std::clog << "Address: " << get<0>(peer.second) << std::endl;
        }
    }

    if (config.mDryRun || *config.mHelp) {
        return(0);
    }

    config.mPeerService.StartService(config.mListenAddress, [&signer](const p2p::FrostMessage &m) { signer->Accept(m); });

    signer_service::SignerService signerService(config.mTaskService);
    signerService.AddSigner(signer);

    auto aggKeyFuture = signerService.NegotiateKey(signer->GetLocalPubKey());
    xonly_pubkey shared_pk = aggKeyFuture.get();

    if (config.mDoSign) {
        auto nonce_res = signerService.PublishNonces(signer->GetLocalPubKey(), 2);
        nonce_res.wait();

        uint256 message;
        CSHA256().Write((unsigned char *) config.mInput.data(), config.mInput.length()).Finalize(message.data());

        auto sign_res = signerService.Sign(signer->GetLocalPubKey(), message, 0);
        signature sig = sign_res.get();

        std::cout << HexStr(sig) << std::endl;
    }

}
