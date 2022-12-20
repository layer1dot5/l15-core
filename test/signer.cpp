
#include <string>
#include <vector>
#include <sstream>
#include <deque>

#include <unistd.h>

#include <boost/container/flat_map.hpp>

#include "CLI11.hpp"
#include "common.hpp"
#include "version.hpp"
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
const char * const TRACE = "--debug-trace,-t";
const char * const DRYRUN = "--dry-run,-d";
const char * const DOSIGN = "--sign,-s";



class Signer
{
    CLI::App mApp;

public:
    size_t mVerbose;
    bool mTrace;
    bool mDryRun;
    bool mDoSign;
    std::string mSecKey;
    std::string mListenAddress;
    std::shared_ptr<l15::service::GenericService> mTaskService;
    WalletApi mWallet;
    boost::container::flat_map<xonly_pubkey, std::string, l15::less<xonly_pubkey>> m_peers;
    std::string mInput;

    Signer();
    ~Signer() = default;

    void ProcessConfig(int argc, const char *const argv[])
    {
        try {
            mApp.parse(argc, argv);
        }
        catch (const CLI::ParseError &e) {
            mApp.exit(e);
            std::rethrow_exception(std::current_exception());
        }
    }

    void Print() const {
        std::clog << "seckey: " << mSecKey << "\n";
        std::clog << "listen-addr: " << mListenAddress << "\n";
        for (const auto& p: m_peers) {
            std::clog << "peer: " << p.second << '|' << hex(p.first) << "\n";
        }
        std::clog << std::endl;
    }

};


Signer::Signer()
: mApp("Tool to generate threshold signature", "signer")
, mVerbose(0), mDryRun(false), mDoSign(false)
, mTaskService(std::make_shared<service::GenericService>(10))
, mWallet()
{
    mApp.set_config(CONF, "signer.conf", "Read the configuration file");
    mApp.set_version_flag("--version", [](){ return std::string("Test Signer\nL15 components' versions:\n") + Version::MakeFullVersion(); });
    mApp.set_help_flag("--help,-h", "Display this help information and exit");

    mApp.add_flag(VERBOSE, mVerbose, "Log more traces including configuration, -vv forces to print all the peer from configuration");

    mApp.add_flag(TRACE, mTrace, "Print debug traces to log");

    mApp.add_flag(DRYRUN, mDryRun, "Does not run signer service, just checks config and prints its output");

    mApp.add_flag(DOSIGN, mDoSign, "Indicates does the peer participate in signature creation");

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

            m_peers.emplace(move(pk), move(addr));
        }
    },
    "Signing counterparty peer address")->configurable(true)->take_all();

    mApp.add_option(INPUT,
                    mInput,
                    "Input message to sign")->configurable(true);
}

error_handler error_hdl = [](Error&& e) { std::cerr << (std::ostringstream() << "Fatal error: " << e.what() << ": " << e.details()).str() << std::endl; exit(1); };

int main(int argc, char* argv[])
{
    try {
        std::deque<p2p::frost_message_ptr> message_cache;
        std::mutex message_cache_mutex;
        std::atomic<bool> agg_pubkey_ready = false;
        Signer config;
        config.ProcessConfig(argc, argv);

        if (config.mVerbose > 1) config.Print();

        seckey sk;

        if (!config.mSecKey.empty()) {
            sk = ParseHex(config.mSecKey);
        }

        size_t N = config.m_peers.size();
        size_t K = (N % 2) ? (N + 1) / 2 : N / 2;

        std::shared_ptr<SignerApi> signer = make_shared<SignerApi>(
                config.mSecKey.empty()
                ? l15::core::ChannelKeys(config.mWallet.Secp256k1Context())
                : l15::core::ChannelKeys(config.mWallet.Secp256k1Context(), std::move(sk)),
                N, K,
                error_hdl);

        if (config.mVerbose) {
            std::clog << "pid: " << getpid() << "\n";
            std::clog << "sign: " << K << "-of-" << N << "\n";
            std::clog << "sk: " << HexStr(signer->GetSecKey()) << "\n";
            std::clog << "pk: " << HexStr(signer->GetLocalPubKey()) << std::endl;
        }

        if (config.mDryRun) {
            return 0;
        }

        std::unique_ptr<ZmqService> peerService = std::make_unique<ZmqService>(
                config.mWallet.Secp256k1Context(),
                config.mTaskService,
                signer->GetLocalPubKey(),
                config.mDoSign ? p2p::FROST_MESSAGE::SIGNATURE_SHARE : p2p::FROST_MESSAGE::KEY_SHARE,
                config.mTrace);

        for (const auto &peer: config.m_peers) {
            if (peer.first != signer->GetLocalPubKey()) {
                peerService->AddPeer(xonly_pubkey(peer.first), std::string(peer.second));

                if (config.mVerbose == 2) {
                    std::clog << "\nPeer:    " << hex(peer.first) << "\n";
                    std::clog << "Address: " << peer.second << std::endl;
                }
            }
        }

        //config.mPeerService.SetSelfPubKey(signer->GetLocalPubKey());
        signer->SetPublisher([&peerService, verbose = config.mVerbose](p2p::frost_message_ptr m) {
            if (verbose == 2) std::clog << ">>>> " << m->ToString() << std::endl;
            peerService->Publish(move(m));
        });

        for (const auto &peer: peerService->GetPeersMap()) {
            signer->AddPeer(xonly_pubkey(peer.first), [&, pk = peer.first, verbose = config.mVerbose](p2p::frost_message_ptr m) {
                if (verbose == 2)
                    std::clog << (std::ostringstream() << ">>>> " << hex(pk).substr(0, 8) << "... | " << m->ToString()).str() << std::endl;
                peerService->Send(pk, move(m));
            });
        }

        if (config.mVerbose) std::clog << "Creating signer service =================================================" << std::endl;
        signer_service::SignerService signerService(config.mTaskService);
        signerService.AddSigner(signer);

        if (config.mVerbose) std::clog << "Starting network service ================================================" << std::endl;
        peerService->StartService(config.mListenAddress, [&, signer, verbose = config.mVerbose](p2p::frost_message_ptr m) {
            if ((m->id == p2p::FROST_MESSAGE::SIGNATURE_COMMITMENT || m->id == p2p::FROST_MESSAGE::SIGNATURE_SHARE) && !agg_pubkey_ready) {
                {
                    std::lock_guard lock(message_cache_mutex);
                    message_cache.emplace_back(m);
                }
                if (verbose == 2)
                    std::clog << (std::ostringstream() << "<<<< " << m->ToString() << " >>>> move to cache until agg pubkey is ready").str()
                              << std::endl;
                return;
            }

            if (m->id == p2p::FROST_MESSAGE::SIGNATURE_SHARE) {
                std::unique_lock lock(message_cache_mutex);
                if (std::find_if(message_cache.begin(), message_cache.end(), [m](auto m1) { return m1->pubkey == m->pubkey; }) !=
                    message_cache.end()) {
                    message_cache.emplace_back(m);
                    lock.unlock();
                    if (verbose == 2)
                        std::clog << (std::ostringstream() << "<<<< " << m->ToString()
                                                           << " >>>> move to cache until sig commitment is processed").str() << std::endl;
                    return;
                }
            }

            if (verbose == 2) std::clog << (std::ostringstream() << "<<<< " << m->ToString()).str() << std::endl;
            signerService.Accept(signer->GetLocalPubKey(), m);
        });


        std::future<void> nonce_res;
        //if (config.mDoSign) {
        if (config.mVerbose) std::clog << "Commiting future signature nonces =======================================" << std::endl;
        nonce_res = signerService.PublishNonces(signer->GetLocalPubKey(), 1);
        nonce_res.wait();
        //}

        if (config.mVerbose) std::clog << "Aggregated key negotiation =====================================" << std::endl;
        auto aggKeyFuture = signerService.NegotiateKey(signer->GetLocalPubKey());
        xonly_pubkey shared_pk = aggKeyFuture.get();
        agg_pubkey_ready = true;

        std::cout << "\nagg_pk:" << hex(shared_pk) << std::endl;

        std::this_thread::sleep_for(std::chrono::milliseconds(1000)); //Just get some time to handle what coming to the message cache ^^^

        bool res = true;
        if (config.mDoSign) {
            while (true) {
                p2p::frost_message_ptr m;
                {
                    std::lock_guard lock(message_cache_mutex);
                    if (message_cache.empty())
                        break;

                    m = message_cache.front();
                    message_cache.pop_front();
                }

                if (config.mVerbose == 2) std::clog << (std::ostringstream() << "==== " << m->ToString()).str() << std::endl;
                signerService.Accept(signer->GetLocalPubKey(), move(m));
            }

            uint256 message;
            CSHA256().Write((unsigned char *) config.mInput.data(), config.mInput.length()).Finalize(message.data());

            if (config.mVerbose) std::clog << "Signing =================================================================" << std::endl;
            auto sign_res = signerService.Sign(signer->GetLocalPubKey(), message, 0);
            signature sig = sign_res.get();

            std::cout << "sig: " << hex(sig) << std::endl;

            try {
                signer->Verify(message, sig);
            }
            catch (SignatureError &e) {
                res = false;
            }
            std::cout << "verify: " << res << std::endl;

            std::this_thread::sleep_for(std::chrono::seconds(15)); // take time to send messages from queue if any
        }
        else {
            peerService->WaitForConfirmations();
        }

        signer.reset();
        return res ? 0 : 1;
    }
    catch (const CLI::Error& e) {
        return e.get_exit_code();
    }
    catch (const std::exception &e) {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }
}
