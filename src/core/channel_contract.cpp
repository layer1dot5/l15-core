#include "channel_contract.hpp"

namespace l15 {

bool LessByTime(const IChannelContract& first, const IChannelContract& second)
{
    return first.ExecutionLock() != second.ExecutionLock() ? first.ExecutionLock() < second.ExecutionLock() : first.ExpiryLock() < second.ExpiryLock();
}


bool operator==(const IChannelContract &c1, const IChannelContract &c2)
{
    return c1.Amount() == c2.Amount()
           && c1.ExecutionLock() == c2.ExecutionLock()
           && c1.ExpiryLock() == c2.ExpiryLock()
           && c1.CommitPubKeyScript(ContractSideSelector(LOCAL)) == c2.CommitPubKeyScript(ContractSideSelector(LOCAL))
           && c1.CommitPubKeyScript(ContractSideSelector(REMOTE)) == c2.CommitPubKeyScript(ContractSideSelector(REMOTE));
}


//CTransaction ContractLogicDistinguisher::SignedTransaction(const bytevector& commit_txid, uint32_t commit_nout) const
//{
//    auto tx = Transaction(commit_txid, commit_nout);
//    tx.vin[0].scriptWitness.stack = std::move(Witness(tx));
//    return CTransaction(tx);
//}

//std::vector<CTransaction> IContractLogicDistinguisher::MakeSignedTransactions(const bytevector &commit_txid, uint32_t commit_nout)
//{
//    return std::vector<CTransaction>();
//}


}