
#include <memory>
#include <algorithm>
#include <iostream>

#include "channel.hpp"

#include "utils.hpp"
#include "wallet_api.hpp"


namespace l15::core {

CScript TapRootPayContract::CommitPubKeyScript(ContractSideSelector ) const
{
    CScript script;
    script << 1;
    script << GetChannel().Wallet().Bech32Decode(mAddress);
    return script;
}



void Channel::Init(bool balance_is_local)
{
//    CScript script = mKeys.MakeMultiSigScript();
//
//    std::unique_ptr<CMutableTransaction> local(new CMutableTransaction());
//    mWallet.AddTxIn(*local, {script, mUtxoTxid, mUtxoTxNOut});
//    mWallet.AddTxOut(*local, balance_is_local ? mToLocalAddress : mToRemoteAddress, mAmount - OnChainTxFee());
//
//    //bytevector localsig = mWallet.SignSegwitTx(mKeys.RawLocalPrivKey(), *local, mAmount);
//
//    // For simplicity to_local/to_remote outputs are simple P2WPKH
//    mRemoteCommitTxHistory.push_back({std::make_unique<CMutableTransaction>(*local), bytevector(),
//                                      (balance_is_local?std::optional<uint32_t>{}:std::optional<uint32_t>(0)),
//                                      (balance_is_local?std::optional<uint32_t>(0):std::optional<uint32_t>{})});
//
//    mLocalCommitTxHistory.push_back({std::move(local), bytevector(),
//                                     (balance_is_local?std::optional<uint32_t>(0):std::optional<uint32_t>{}),
//                                     (balance_is_local?std::optional<uint32_t>{}:std::optional<uint32_t>(0))});
//
//    std::clog << "GetChannel script hash: " << HexStr(ScriptHash(script)) << std::endl;

}

std::vector<bytevector> Channel::SignLocalCommit() const
{
//    bytevector localsig = mWallet.SignSegwitTx(mKeys.RawLocalPrivKey(), *LocalCommit().Tx, mAmount);
//
//    CKey local_privkey;
//    local_privkey.Set(mKeys.RawLocalPrivKey().begin(), mKeys.RawLocalPrivKey().end(), true);
//    CPubKey LocalPubkey = local_privkey.GetPubKey();
//    CPubKey RemotePubkey(mKeys.RawRemotePubKey().begin(), mKeys.RawRemotePubKey().end());
//
//    bytevector local_pubkey(LocalPubkey.begin(), LocalPubkey.end());
//
//    if(LocalPubkey < RemotePubkey)
//    {
//        return {bytevector(), localsig, LocalCommit().Sig};
//    }
//    else {
//        return {bytevector(), LocalCommit().Sig, localsig};
//    }
}

bytevector Channel::RemoteCommitSignature() const
{
//    return mWallet.SignSegwitTx(mKeys.RawLocalPrivKey(), *RemoteCommit().Tx, mAmount);
}

transaction_psig_t Channel::SignToCloseMutulually(const CAmount local_amount, const CAmount remote_amount) const
{
//    CScript script = mKeys.MakeMultiSigScript();
//
//    transaction_psig_t psig;
//
//    mWallet.AddTxIn(std::get<0>(psig), {script, mUtxoTxid, mUtxoTxNOut});
//    if(local_amount > 0)
//        mWallet.AddTxOut(std::get<0>(psig), ToLocalAddress(), local_amount);
//
//    if(remote_amount > 0)
//        mWallet.AddTxOut(std::get<0>(psig), ToRemoteAddress(), remote_amount);
//
//    std::get<1>(psig) = mWallet.SignSegwitTx(mKeys.RawLocalPrivKey(), std::get<0>(psig), mAmount);
//
//    return psig;
}


CAmount Channel::ControlledLocalBalance() const
{
//    CAmount balance = LocalCommit().ToLocalAmount();
//    for(const auto& c: OfferedContracts())
//    {
//        if(c->IsActive())
//            balance += c->Amount();
//    }
//    return balance;
}

CAmount Channel::ControlledRemoteBalance() const
{
//    CAmount balance = RemoteCommit().ToLocalAmount();
//    for(const auto& c: ReceivedContracts())
//    {
//        if(c->IsActive())
//            balance += c->Amount();
//    }
//    return balance;
}

std::tuple<CAmount, CAmount> Channel::AddAndReactivateContracts(std::shared_ptr<ChannelContract> contract)
{
    CAmount local_balance = ControlledLocalBalance();
    CAmount remote_balance = ControlledRemoteBalance();
    if(local_balance + remote_balance + OnChainTxFee() != Amount())
    {
        std::ostringstream s;
        s << "GetChannel balances (" << local_balance << ", " << remote_balance << ", " << OnChainTxFee() << ") does not match total: " << Amount();
        throw std::runtime_error(s.str());
    }

    if(contract->Direction() == OFFERED)
    {
        mOfferedContracts.emplace_back(contract);
        std::sort(mOfferedContracts.begin(), mOfferedContracts.end());

        for(const auto& c: OfferedContracts())
        {
            c->SetActive((c->Amount() + OnChainTxFee()) <= local_balance);
            if(c->IsActive())
            {
                local_balance -= c->Amount();
            }
        }
    }

    if(contract->Direction() == RECEIVED)
    {
        mReceivedContracts.emplace_back(contract);
        std::sort(mReceivedContracts.begin(), mReceivedContracts.end());

        for(const auto& c: ReceivedContracts())
        {
            c->SetActive((c->Amount() + OnChainTxFee()) <= remote_balance);
            if(c->IsActive())
            {
                remote_balance -= c->Amount();
            }
        }
    }

    return {local_balance, remote_balance};
}


void Channel::AddContract(std::shared_ptr<ChannelContract> contract)
{
//    auto balances = AddAndReactivateContracts(contract);
//
//    CScript script = mKeys.MakeMultiSigScript();
//
//    CommitHtlc local_commit{std::make_unique<CMutableTransaction>()};
//    mWallet.AddTxIn(*local_commit.Tx, {script, mUtxoTxid, mUtxoTxNOut});
//
//    CommitHtlc remote_commit{std::make_unique<CMutableTransaction>(*local_commit.Tx)};
//
//    //std::vector<std::shared_ptr<IChannelContract>> local_outs;
//    local_commit.Outputs.reserve(OfferedContracts().size() + ReceivedContracts().size() + 2);
//
//    //std::vector<std::shared_ptr<IChannelContract>> remote_outs;
//    remote_commit.Outputs.reserve(OfferedContracts().size() + ReceivedContracts().size() + 2);
//
//    for(const auto& c: OfferedContracts())
//    {
//        if(c->IsActive())
//        {
//            local_commit.Outputs.emplace_back(std::static_pointer_cast<IChannelContract>(c));
//            remote_commit.Outputs.emplace_back(std::static_pointer_cast<IChannelContract>(c));
//        }
//    }
//
//    for(const auto& c: ReceivedContracts())
//    {
//        if(c->IsActive())
//        {
//            local_commit.Outputs.emplace_back(std::static_pointer_cast<IChannelContract>(c));
//            remote_commit.Outputs.emplace_back(std::static_pointer_cast<IChannelContract>(c));
//        }
//    }
//
//    if(std::get<LOCAL>(balances) > 0)
//    {
//        local_commit.Outputs.emplace_back(std::shared_ptr<IChannelContract>(new TapRootPayContract(*this, std::get<LOCAL>(balances), std::string(ToLocalAddress()))));
//        remote_commit.Outputs.emplace_back(std::shared_ptr<IChannelContract>(new TapRootPayContract(*this, std::get<LOCAL>(balances), std::string(ToLocalAddress()))));
//    }
//
//    if(std::get<REMOTE>(balances) > 0)
//    {
//        local_commit.Outputs.emplace_back(std::shared_ptr<IChannelContract>(new TapRootPayContract(*this, std::get<REMOTE>(balances), std::string(ToRemoteAddress()))));
//        remote_commit.Outputs.emplace_back(std::shared_ptr<IChannelContract>(new TapRootPayContract(*this, std::get<REMOTE>(balances), std::string(ToRemoteAddress()))));
//    }
//
//    std::sort(local_commit.Outputs.begin(), local_commit.Outputs.end(), LessByOutNum(LOCAL));
//    std::sort(remote_commit.Outputs.begin(), remote_commit.Outputs.end(), LessByOutNum(REMOTE));
//
//
//    uint32_t i = 0;
//    for(const auto& out: local_commit.Outputs)
//    {
//        const std::string addr = out->Address(ContractSideSelector(LOCAL));
//
//        mWallet.AddTxOut(*local_commit.Tx, addr, out->Amount());
//
//        if(addr == mToLocalAddress)
//            local_commit.ToLocalOutNumber = i;
//        if(addr == mToRemoteAddress)
//            local_commit.ToRemoteOutNumber = i;
//
//        ++i;
//    }
//
//    i = 0;
//    for(const auto& out: remote_commit.Outputs)
//    {
//        const std::string addr = out->Address(ContractSideSelector(REMOTE));
//
//        mWallet.AddTxOut(*remote_commit.Tx, addr, out->Amount());
//
//        if(addr == mToRemoteAddress)
//            remote_commit.ToLocalOutNumber = i;
//        if(addr == mToLocalAddress)
//            remote_commit.ToRemoteOutNumber = i;
//
//        ++i;
//    }
//
//    remote_commit.Sig = mWallet.SignSegwitTx(mKeys.GetLocalPrivKey(), *remote_commit.Tx, Amount());
//
//    mLocalCommitTxHistory.emplace_back(std::move(local_commit));
//    mRemoteCommitTxHistory.emplace_back(std::move(remote_commit));
}


}