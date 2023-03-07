#include "onchain_net_service.hpp"

namespace l15 {

    void l15::p2p::OnChainWriter::Write() {
        auto serviceChainApi = std::make_unique<ChainApi>(Bech32Coder<IBech32Coder::L15, IBech32Coder::REGTEST>(),
                                                          std::move(mConfFactory.conf.ChainValues(config::L15NODE)),
                                                          "l15node-cli");
        size_t block_cnt = 0;
        size_t tx_cnt = 0;

        serviceChainApi->CreateWallet("test");

        onchain_service::OnChainService service(std::move(serviceChainApi));

        service.SetNewBlockHandler(ChainTracer < CBlockHeader > {block_cnt});
        service.SetNewTxHandler(ChainTracer < CTransaction > {tx_cnt});

        service.Start();

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

// Service has started
        auto clientChainApi = std::make_shared<ChainApi>(Bech32Coder<IBech32Coder::L15, IBech32Coder::REGTEST>(),
                                                         std::move(mConfFactory.conf.ChainValues(config::L15NODE)),
                                                         "l15node-cli");
        ChannelKeys outkey(m_client.m_wallet.Secp256k1Context());

        ChannelKeys key(m_client.m_wallet.Secp256k1Context());
        std::string address = clientChainApi->Bech32Encode(key.GetPubKey());

        UniValue blocks;
        blocks.read(clientChainApi->GenerateToAddress(address, "1"));

        UniValue block;
        block.read(clientChainApi->GetBlock(blocks[0].getValStr(), "1"));

        COutPoint out_point;
        CTxOut tx_out;

        std::tie(out_point, tx_out) = clientChainApi->CheckOutput(block["tx"][0].getValStr(), address);

        CHECK(tx_out.nValue == ParseAmount("4096"));

        CMutableTransaction op_return_tx;
        op_return_tx.vin.emplace_back(CTxIn(out_point));

        CScript outpubkeyscript;
        outpubkeyscript << 1;
        outpubkeyscript << outkey.GetPubKey();

        CScript outopreturnscript;
        outopreturnscript << OP_RETURN;
        outopreturnscript << ParseHex("abcdef1234567890");

        op_return_tx.vout.emplace_back(CTxOut(ParseAmount("4095.99"), outpubkeyscript));
        op_return_tx.vout.emplace_back(CTxOut(0, outopreturnscript));

        bytevector sig = m_client.m_wallet.SignTaprootTx(key.GetLocalPrivKey(), op_return_tx, 0, {tx_out}, {});
        op_return_tx.vin.front().scriptWitness.stack.emplace_back(sig);

        clientChainApi->GenerateToAddress(address, "100"); // Make coinbase tx mature

        CHECK_NOTHROW(clientChainApi->SpendTx(CTransaction(op_return_tx)));
// End of inserted code

        CHECK_NOTHROW(service.Stop());

        std::clog << "On-Chain service is stopped" << std::endl;

        REQUIRE(block_cnt == 101);
        REQUIRE(tx_cnt == 101);
    }

    void l15::p2p::OnChainService::WaitForConfirmations() {
        m_zmq->WaitForConfirmations();
    }

    void l15::p2p::OnChainService::Connect(const l15::xonly_pubkey &pubkey,
                                           std::function<void(p2p::frost_message_ptr)> handler) {
        m_zmq->Connect(pubkey, handler);
    }

    void l15::p2p::OnChainService::Send(const l15::xonly_pubkey &pk, l15::p2p::frost_message_ptr m,
                                        std::function<void()> on_error) {
        m_zmq->Send(pk, m, on_error);
    }

    void l15::p2p::OnChainService::Publish(l15::p2p::frost_message_ptr m,
                                           std::function<void(const xonly_pubkey &, p2p::frost_message_ptr)> on_send,
                                           std::function<void(const xonly_pubkey &, p2p::frost_message_ptr)> on_error) {
        m_zmq->Publish(m, on_send, on_error);
    }

    void l15::p2p::OnChainService::AddPeer(l15::xonly_pubkey &&pk, string &&addr) {
        m_zmq->AddPeer(move(pk), move(addr));
    }

    const ZmqService::peers_map &l15::p2p::OnChainService::GetPeersMap() const {
        return m_zmq->GetPeersMap();
    }

    const std::function<void(p2p::frost_message_ptr)> &l15::p2p::OnChainService::GetMessageHandler() {
        return m_zmq->GetMessageHandler();
    }

} // namespace l15