#include "onchain_net_service.hpp"

#include "logging.h"
#include "univalue.h"

namespace l15::p2p {

    OnChainWriterV1::OnChainWriterV1(const l15::Config &config, const std::string &walletName) : m_wallet(),
        m_onChainService(make_unique<core::ChainApi>(Bech32Coder<IBech32Coder::L15, IBech32Coder::REGTEST>(), std::move(config.ChainValues(config::L15NODE)), "l15node-cli")),
        m_outKey(m_wallet.Secp256k1Context()),
        m_key(m_wallet.Secp256k1Context()),
        m_walletName(walletName){

        std::string movableWalletName = walletName;

        m_onChainService.ChainAPI().CreateWallet(std::move(movableWalletName));

        m_onChainService.SetNewBlockHandler(ChainTracer<CBlockHeader>{m_blockCnt});
        m_onChainService.SetNewTxHandler(ChainTracer<CTransaction>{m_txCnt});

        m_onChainService.Start();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        m_address = m_onChainService.ChainAPI().Bech32Encode(m_key.GetPubKey());
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    void OnChainWriterV1::Write(const std::string &payload) {
        auto optionalUtxo = findGoodUtxo(100000);
        if (!optionalUtxo) {
            throw std::logic_error("No good UTXO for writing a transaction");
        }

        COutPoint out_point;
        CTxOut tx_out;

        std::tie(out_point, tx_out) = m_onChainService.ChainAPI().CheckOutput(optionalUtxo->txid, m_address);

        CMutableTransaction op_return_tx;
        op_return_tx.vin.emplace_back(CTxIn(out_point));

        CScript outPubKeyScript;
        outPubKeyScript << 1;
        outPubKeyScript << m_outKey.GetPubKey();

        CScript outOpReturnScript;
        outOpReturnScript << OP_RETURN;
        outOpReturnScript << ParseHex(payload);

        op_return_tx.vout.emplace_back(CTxOut(100000, outPubKeyScript));
        op_return_tx.vout.emplace_back(CTxOut(0, outOpReturnScript));

        bytevector sig = m_wallet.SignTaprootTx(m_key.GetLocalPrivKey(), op_return_tx, 0, {tx_out}, {});
        op_return_tx.vin.front().scriptWitness.stack.emplace_back(sig);

        m_onChainService.ChainAPI().SpendTx(CTransaction(op_return_tx));
    }

    OnChainWriterV1 &OnChainWriterV1::operator<<(const std::string &payload) {
        Write(payload);
        return (*this);
    }

    size_t OnChainWriterV1::getBlockCnt() const {
        return m_blockCnt;
    }

    size_t OnChainWriterV1::getTxCnt() const {
        return m_txCnt;
    }

    const string &OnChainWriterV1::getAddress() const {
        return m_address;
    }

    /*
     * As for now it returns only the first spendable UTXO with some minimal amount of Satoshi
     * TODO: Add minimal and maximal satoshis filter to ListUnspent
     */
    std::optional<l15::core::Utxo> OnChainWriterV1::findGoodUtxo(CAmount minSatoshi) {
        auto utxos = m_onChainService.ChainAPI().ListUnspent(m_address, m_walletName);
        for(const auto &utxo: utxos) {
            if (!utxo.spendable) {
                continue;
            }
            if (ParseAmount(utxo.amount) >= minSatoshi) {
                return utxo;
            }
        }

        return {};
    }

    void OnChainWriterV1::generateBlocks(const std::string &amount) {
        m_onChainService.ChainAPI().GenerateToAddress(m_address, amount);
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
        //m_zmq->Send(pk, m, on_error);
        m_writer->Write(m->ToString());
    }

    void OnChainService::Publish(frost_message_ptr m,
                                           std::function<void(const xonly_pubkey &, frost_message_ptr)> on_send,
                                           std::function<void(const xonly_pubkey &, frost_message_ptr)> on_error) {
        //m_zmq->Publish(m, on_send, on_error);
        m_writer->Write(m->ToString());
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

    OnChainService::OnChainService( const AbstractOnChainWriter::Ptr &writer,
                                    const secp256k1_context_struct *ctx,
                                    std::shared_ptr<service::GenericService> srv,
                                    std::function<bool(frost_message_ptr)> msg_filter)
            : m_writer(writer), m_zmq(std::make_shared<ZmqService>(ctx, srv, msg_filter)) {
    }

    ZmqService::Ptr OnChainService::getZmq() const {
        return m_zmq;
    }

} // namespace l15::p2p
