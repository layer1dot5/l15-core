#pragma once

#include <memory>
#include <vector>
#include <iterator>

#include "smartinserter.hpp"

#include "consensus/amount.h"
#include "script/script.h"
#include "script/interpreter.h"
#include "primitives/transaction.h"

#include "common.hpp"


namespace l15 {

class WalletApi;
class Channel;
class IChannelContract;

enum ContractDirection {
    OFFERED,
    RECEIVED
};


class ContractLogicDistinguisher
{
public:
    virtual ~ContractLogicDistinguisher() = default;
    virtual const IChannelContract& Contract() const = 0;
    virtual CScript FundingScript() const = 0;
    virtual CMutableTransaction Transaction(uint256 commit_txid, uint32_t commit_nout) const = 0;
    virtual bytevector Signature(const CMutableTransaction& tx, int hashtype = SIGHASH_ALL) const = 0;
    bytevector Signature(uint256 commit_txid, uint32_t commit_nout, int hashtype = SIGHASH_ALL) const { return Signature(Transaction(commit_txid, commit_nout)); };
    virtual std::vector<bytevector> Witness(const CMutableTransaction& tx) const = 0;
    std::vector<bytevector> Witness(uint256 commit_txid, uint32_t commit_nout) const { return Witness(Transaction(commit_txid, commit_nout)); }

    virtual std::unique_ptr<ContractLogicDistinguisher> Parent() const = 0;

    template<typename InsertIterator>
    InsertIterator ChainSignedTransactions(InsertIterator it, uint256 commit_txid, uint32_t commit_nout) const
    {
        auto parent = Parent();
        if(parent != nullptr)
        {
            it = Parent()->template ChainSignedTransactions(it, commit_txid, commit_nout);

            auto prev_tx = std::prev(it);
            CMutableTransaction tx = Transaction(prev_tx->GetHash(), 0);
            auto witness = Witness(tx);
            for(auto WitIt = witness.begin(); WitIt != witness.end(); ++WitIt)
            {
                tx.vin[0].scriptWitness.stack.insert(tx.vin[0].scriptWitness.stack.begin(), std::move(*WitIt));
            }
            *it = tx;
        }
        else
        {
            CMutableTransaction tx = Transaction(commit_txid, commit_nout);
            auto witness = Witness(tx);
            for(auto WitIt = witness.begin(); WitIt != witness.end(); ++WitIt)
            {
                tx.vin[0].scriptWitness.stack.insert(tx.vin[0].scriptWitness.stack.begin(), std::move(*WitIt));
            }
            *it = tx;
        }
        return ++it;
    }
};


enum ContractSide {
/**
 * Regarding to commits, LOCAL commit is received from other side
 * and this(local) side are owning the commit and may publish it on-chain.
 * Thus this side keys, addressed as LOCAL are LOCAL keys.
 */
    LOCAL,


/**
 * Regarding to commits, REMOTE commit is created locally to pass to other side.
 * Thus this side keys, addressed by contract as LOCAL at runtime,
 * will be REMOTE for owning side and visa-versa.
 */
    REMOTE
};


enum ContractRole {
    RECEIVER = 0,
    SENDER = 1
};

class ContractSideSelector
{
    const ContractSide mSide;
public:
    ContractSideSelector(ContractSide side) : mSide(side) {}
    template<class T> T& select(T& local, T& remote) const { return mSide == LOCAL ? local : remote; }
};


class IChannelContract {
public:
    virtual ~IChannelContract() = default;

    virtual const Channel& GetChannel() const = 0;

    virtual CAmount Amount() const = 0;
    virtual uint32_t ExecutionLock() const = 0;
    virtual uint32_t ExpiryLock() const = 0;
    virtual CScript CommitPubKeyScript(ContractSideSelector ) const = 0;
    virtual std::string Address(ContractSideSelector ) const = 0;

};

extern bool LessByTime(const IChannelContract& first, const IChannelContract& second);

class LessByOutNum
{
    const ContractSideSelector selector;
public:
    LessByOutNum(ContractSide side) : selector(side) {}
    bool operator()(const std::shared_ptr<IChannelContract> &first, const std::shared_ptr<IChannelContract> &second)
    {
        if(first->Amount() != second->Amount())
            return first->Amount() < second->Amount();
        else
        {
            int cmpres = memcmp(first->CommitPubKeyScript(selector).data(), second->CommitPubKeyScript(selector).data(),
                                std::min(first->CommitPubKeyScript(selector).size(), second->CommitPubKeyScript(selector).size()));
            if(cmpres != 0)
                return cmpres < 0;
            else if(first->CommitPubKeyScript(selector).size() != second->CommitPubKeyScript(selector).size())
                return first->CommitPubKeyScript(selector).size() < second->CommitPubKeyScript(selector).size();
            else if(first->ExpiryLock() != second->ExpiryLock())
                return first->ExpiryLock() < second->ExpiryLock();
            else
                return first->ExecutionLock() < second->ExecutionLock();
        }
    }
};

extern bool operator==(const IChannelContract& c1, const IChannelContract& c2);


class ChannelContract: public virtual IChannelContract {
    const Channel& mChannel;
    bool mIsActive;
public:

    explicit ChannelContract(const Channel& channel) : mChannel(channel), mIsActive(false) {}

    virtual ContractDirection Direction() const = 0;

    const Channel& GetChannel() const override { return mChannel; }

    void SetActive(bool is_active) { mIsActive = is_active; }
    bool IsActive() const { return mIsActive; }
};

}
