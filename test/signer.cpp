
#include <string>
#include <vector>
#include <sstream>
#include <deque>
#include <memory>
#include <ranges>

#include <unistd.h>

#include <boost/container/flat_map.hpp>

#include "async_result.hpp"

#include "CLI11.hpp"
#include "common.hpp"
#include "channel_keys.hpp"
#include "wallet_api.hpp"
#include "frost_signer.hpp"
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



class TestSigner
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
    boost::container::flat_map<xonly_pubkey, std::string> m_peers;
    std::string mInput;

    TestSigner();
    ~TestSigner() = default;

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


TestSigner::TestSigner()
: mApp("Tool to generate threshold signature", "signer")
, mVerbose(0), mDryRun(false), mDoSign(false)
, mTaskService(std::make_shared<service::GenericService>(10))
, mWallet()
{
    mApp.set_config(CONF, "signer.conf", "Read the configuration file");
    mApp.set_version_flag("--version", [](){ return std::string("L15 test signer v: ") + PACKAGE_VERSION; });
    mApp.set_help_flag("--help,-h", "Display this help information and exit");

    mApp.add_flag(VERBOSE, mVerbose, "Log more traces including configuration, -vv forces to print all the peer from configuration");

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


int main(int argc, char* argv[])
{
    try {
        std::deque<p2p::frost_message_ptr> message_cache;
        std::mutex message_cache_mutex;
        std::atomic_bool agg_pubkey_ready = false;
        TestSigner config;
        config.ProcessConfig(argc, argv);

        if (config.mVerbose > 1) config.Print();

        seckey sk;

        if (!config.mSecKey.empty()) {
            sk = ParseHex(config.mSecKey);
        }

        core::ChannelKeys keypair = config.mSecKey.empty()
                             ? l15::core::ChannelKeys(config.mWallet.Secp256k1Context())
                             : l15::core::ChannelKeys(config.mWallet.Secp256k1Context(), std::move(sk));

        if (config.mVerbose) {
            std::clog << "pid: " << getpid() << "\n";
//            std::clog << "sign: " << K << "-of-" << N << "\n";
            std::clog << "sk: " << hex(keypair.GetLocalPrivKey()) << "\n";
            std::clog << "pk: " << hex(keypair.GetLocalPubKey()) << std::endl;
        }

        if (config.mDryRun) {
            return 0;
        }

        std::shared_ptr<ZmqService> peerService = std::make_shared<ZmqService>(
                config.mWallet.Secp256k1Context(),
                config.mTaskService, [&, verbose = config.mVerbose](p2p::frost_message_ptr m) {
                    if ((m->id == p2p::FROST_MESSAGE::SIGNATURE_COMMITMENT || m->id == p2p::FROST_MESSAGE::SIGNATURE_SHARE) && !agg_pubkey_ready) {
                        {
                            std::lock_guard lock(message_cache_mutex);
                            message_cache.emplace_back(m);
                        }
                        if (verbose == 2)
                            std::clog << (std::ostringstream() << "<<<< " << m->ToString() << " >>>> move to cache until agg pubkey is ready").str()
                                      << std::endl;
                        return false;
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
                            return false;
                        }
                    }

                    if (verbose == 2) std::clog << (std::ostringstream() << "<<<< " << m->ToString()).str() << std::endl;
                    return true;
                });

        for (const auto &peer: config.m_peers) {
            if (peer.first != keypair.GetLocalPubKey()) {
                peerService->AddPeer(xonly_pubkey(peer.first), std::string(peer.second));

                if (config.mVerbose == 2) {
                    std::clog << "\nPeer:    " << hex(peer.first) << "\n";
                    std::clog << "Address: " << peer.second << std::endl;
                }
            }
        }

        if (config.mVerbose) std::clog << "Starting signer =================================================" << std::endl;
        auto signerService = std::make_shared<signer_service::SignerService>(config.mTaskService);

        auto signer = make_shared<frost::FrostSigner>(keypair, config.m_peers | std::views::keys, signerService, peerService);
        signer->Start();

        std::promise<xonly_pubkey> aggpk_promise;
        auto aggpk_res = aggpk_promise.get_future();

        signer->AggregateKey(cex::make_async_result<const xonly_pubkey&>(
                [](const xonly_pubkey& aggpk, std::promise<xonly_pubkey>&& p) { p.set_value(aggpk); },
                [](std::promise<xonly_pubkey>&& p){ p.set_exception(std::current_exception()); },
                move(aggpk_promise)));

        xonly_pubkey shared_pk = aggpk_res.get();
        agg_pubkey_ready = true;

        std::cout << "\nagg_pk:" << hex(shared_pk) << std::endl;

        if (config.mDoSign) {
            if (config.mVerbose) std::clog << "Commiting future signature nonces =======================================" << std::endl;

            std::promise<void> nonce_promise;
            auto nonce_res = nonce_promise.get_future();

            signer->CommitNonces(1, cex::make_async_result<void>(
                    [](std::promise<void>&& p){p.set_value();},
                    [](std::promise<void>&& p){p.set_exception(std::current_exception());},
                    move(nonce_promise)));

            nonce_res.wait();
        }

//        std::this_thread::sleep_for(std::chrono::milliseconds(1000)); //Just get some time to handle what coming to the message cache ^^^
//
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

                peerService->GetMessageHandler()(move(m));
            }

            scalar message;
            CSHA256().Write((unsigned char *) config.mInput.data(), config.mInput.length()).Finalize(message.data());

            if (config.mVerbose) std::clog << "Signing =================================================================" << std::endl;

            std::promise<signature> sig_promise;

            auto sig_res = sig_promise.get_future();

            signer->Sign(message, message, cex::make_async_result<signature>(
                    [](signature sig, std::promise<signature>&& p){p.set_value(sig);},
                    [](std::promise<signature>&& p){p.set_exception(std::current_exception());},
                    move(sig_promise)));

            signature sig = sig_res.get();

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
    catch (const Error& e) {
        std::cerr << e.what() << ": " << e.details() << std::endl;
        return 1;
    }
    catch (const std::exception &e) {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }
}
