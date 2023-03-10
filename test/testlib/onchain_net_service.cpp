#include "onchain_net_service.hpp"

#include "logging.h"
#include "univalue/include/univalue.h"
#include "channel_keys.hpp"

namespace l15::p2p {

    OnChainWriterV1::OnChainWriterV1(const Config &config) : m_wallet(),
        m_chainApi(make_unique<core::ChainApi>(Bech32Coder<IBech32Coder::L15, IBech32Coder::REGTEST>(), std::move(config.ChainValues(config::L15NODE)), "l15node-cli")) {
    }

    void OnChainWriterV1::Write(const std::string &payload) {
// Service has started
        l15::core::ChannelKeys outkey(m_wallet.Secp256k1Context());
        l15::core::ChannelKeys key(m_wallet.Secp256k1Context());
        std::string address = m_chainApi->Bech32Encode(key.GetPubKey());

        UniValue blocks;
        blocks.read(m_chainApi->GenerateToAddress(address, "1"));

        UniValue block;
        block.read(m_chainApi->GetBlock(blocks[0].getValStr(), "1"));

        COutPoint out_point;
        CTxOut tx_out;

        std::tie(out_point, tx_out) = m_chainApi->CheckOutput(block["tx"][0].getValStr(), address);

        CMutableTransaction op_return_tx;
        op_return_tx.vin.emplace_back(CTxIn(out_point));

        CScript outpubkeyscript;
        outpubkeyscript << 1;
        outpubkeyscript << outkey.GetPubKey();

        CScript outopreturnscript;
        outopreturnscript << OP_RETURN;
        outopreturnscript << ParseHex(payload);

        op_return_tx.vout.emplace_back(CTxOut(ParseAmount("4095.99"), outpubkeyscript));
        op_return_tx.vout.emplace_back(CTxOut(0, outopreturnscript));

        bytevector sig = m_wallet.SignTaprootTx(key.GetLocalPrivKey(), op_return_tx, 0, {tx_out}, {});
        op_return_tx.vin.front().scriptWitness.stack.emplace_back(sig);

        m_chainApi->GenerateToAddress(address, "100"); // Make coinbase tx mature
    }

    OnChainWriterV1 &OnChainWriterV1::operator<<(const string &payload) {
        Write(payload);
        return (*this);
    }

    void OnChainService::WaitForConfirmations() {
        m_zmq->WaitForConfirmations();
    }

    void OnChainService::Connect(const xonly_pubkey &pubkey,
                                           std::function<void(frost_message_ptr)> handler) {
        m_zmq->Connect(pubkey, handler);
    }

    void OnChainService::Send(const xonly_pubkey &pk, frost_message_ptr m,
                                        std::function<void()> on_error) {
        m_zmq->Send(pk, m, on_error);
    }

    void OnChainService::Publish(frost_message_ptr m,
                                           std::function<void(const xonly_pubkey &, frost_message_ptr)> on_send,
                                           std::function<void(const xonly_pubkey &, frost_message_ptr)> on_error) {
        m_zmq->Publish(m, on_send, on_error);
    }

    void OnChainService::AddPeer(xonly_pubkey &&pk, string &&addr) {
        m_zmq->AddPeer(move(pk), move(addr));
    }

    const ZmqService::peers_map &OnChainService::GetPeersMap() const {
        return m_zmq->GetPeersMap();
    }

    const std::function<void(frost_message_ptr)> &OnChainService::GetMessageHandler() {
        return m_zmq->GetMessageHandler();
    }

    OnChainService::OnChainService(const secp256k1_context_struct *ctx,
                                        std::shared_ptr<service::GenericService> srv,
                                        std::function<bool(frost_message_ptr)> msg_filter)
            : m_zmq(std::make_shared<ZmqService>(ctx, srv, msg_filter)) {
    }

    ZmqService::Ptr OnChainService::getZmq() const {
        return m_zmq;
    }

} // namespace l15::p2p