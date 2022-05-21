#pragma once

#include <tuple>
#include <optional>
#include <sstream>

#include "common.hpp"
#include "wallet_api.hpp"
#include "channel_keys.hpp"
#include "channel_contract.hpp"


namespace l15 {

class Channel;

class TapRootPayContract : public IChannelContract
{
    const Channel& mChannel;
    CAmount mAmount;
    std::string mAddress;
public:
    TapRootPayContract(const class Channel& channel, CAmount amount, std::string&& address) noexcept
            : mChannel(channel),
              mAmount(amount),
              mAddress(std::move(address)) {}
    CAmount Amount() const override { return mAmount; }
    uint32_t ExecutionLock() const override { return 0; }
    uint32_t ExpiryLock() const override { return 0; }
    CScript CommitPubKeyScript(ContractSideSelector ) const override;
    std::string Address(ContractSideSelector ) const override { return mAddress; }
    const Channel& GetChannel() const override { return mChannel; }

};



struct ChannelStateCommitment {
    transaction_ptr Tx;
    bytevector Sig;
    std::optional<uint32_t> ToLocalOutNumber;
    std::optional<uint32_t> ToRemoteOutNumber;
    std::vector<std::shared_ptr<IChannelContract>> Outputs;

    CAmount ToLocalAmount() const { return ToLocalOutNumber ? Tx->vout.at(*ToLocalOutNumber).nValue : 0; }
    CAmount ToRemoteAmount() const { return ToRemoteOutNumber ? Tx->vout.at(*ToRemoteOutNumber).nValue : 0; }

    uint32_t GetNOut(const IChannelContract& contract) const
    {
        for(uint32_t n = 0; n < Outputs.size(); ++n)
        {
            if(*Outputs[n] == contract)
                return n;
        }
        throw std::invalid_argument("Wrong contract, corresponding output is not found");
    }
};


class Channel
{
private:
    const api::WalletApi& mWallet;

    const CAmount mAmount;
    const uint256 mUtxoTxid;
    const uint32_t mUtxoTxNOut;

    ChannelKeys mKeys;

    const string mToLocalAddress;
    const string mToRemoteAddress;

    CAmount mOnChainTxFee;

    std::vector<ChannelStateCommitment> mLocalCommitTxHistory;
    std::vector<ChannelStateCommitment> mRemoteCommitTxHistory;

    std::vector<std::shared_ptr<ChannelContract>> mOfferedContracts;
    std::vector<std::shared_ptr<ChannelContract>> mReceivedContracts;

    std::tuple<CAmount, CAmount> AddAndReactivateContracts(std::shared_ptr<ChannelContract> contract);

public:
    Channel(const api::WalletApi& wallet, const CAmount amount, uint256 txid, uint32_t nout,
                ChannelKeys&& keys, string&& localaddr, string&& remoteaddr)
        : mWallet(wallet), mAmount(amount), mUtxoTxid(txid), mUtxoTxNOut(nout),
          mKeys(std::move(keys)),
          mToLocalAddress(std::move(localaddr)), mToRemoteAddress(std::move(remoteaddr))
    {}

    const api::WalletApi& Wallet() const { return mWallet; }

    CAmount Amount() const { return mAmount; }

    CAmount ControlledLocalBalance() const;
    CAmount ControlledRemoteBalance() const;


    const uint256& FundingTxId() const { return mUtxoTxid; }
    uint32_t FundingTxOutNum() const { return mUtxoTxNOut; }

    void SetOnChainTxFee(const CAmount fee) { mOnChainTxFee = fee; }
    CAmount OnChainTxFee() const { return mOnChainTxFee; }

    const string& ToLocalAddress() const {return mToLocalAddress; }
    const string& ToRemoteAddress() const {return mToRemoteAddress; }

    ChannelStateCommitment& LocalCommit() { return mLocalCommitTxHistory.back(); }
    const ChannelStateCommitment& LocalCommit() const { return mLocalCommitTxHistory.back(); }
    ChannelStateCommitment& RemoteCommit() { return mRemoteCommitTxHistory.back(); }
    const ChannelStateCommitment& RemoteCommit() const { return mRemoteCommitTxHistory.back(); }

    void AddContract(std::shared_ptr<ChannelContract> contract);

    const std::vector<std::shared_ptr<ChannelContract>>& OfferedContracts() const { return mOfferedContracts; }
    std::vector<std::shared_ptr<ChannelContract>>& OfferedContracts() { return mOfferedContracts; }

    const std::vector<std::shared_ptr<ChannelContract>>& ReceivedContracts() const { return mReceivedContracts; }
    std::vector<std::shared_ptr<ChannelContract>>& ReceivedContracts() { return mReceivedContracts; }

    void Init(bool balance_is_local);
    std::vector<bytevector> SignLocalCommit() const;
    bytevector RemoteCommitSignature() const;

    transaction_psig_t SignToCloseMutulually(CAmount local_amount, CAmount remote_amount) const;
};

typedef std::unique_ptr<Channel> channel_ptr;

}
