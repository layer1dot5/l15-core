
#include "utils.hpp"
#include <memory>
#include "l15/common.hpp"
#include "channel_htlc.hpp"
#include "channel_keys.hpp"

namespace l15 {

CScript ChannelKeys::MakeMultiSigScript() const
{
    CKey local_privkey;
    local_privkey.Set(mRawLocalPrivKey.begin(), mRawLocalPrivKey.end(), true);
    CPubKey LocalPubkey = local_privkey.GetPubKey();
    CPubKey RemotePubkey(mRawRemotePubKey.begin(), mRawRemotePubKey.end());

    bytevector local_pubkey(LocalPubkey.begin(), LocalPubkey.end());

    if(LocalPubkey < RemotePubkey)
    {
        return l15::CreateMultiSigScript({local_pubkey, mRawRemotePubKey});
    }
    else
    {
        return l15::CreateMultiSigScript({mRawRemotePubKey, local_pubkey});
    }

}

const bytevector& ChannelKeys::RawLocalPubKey() const
{
    static bytevector local_pubkey_cache;

    if(local_pubkey_cache.empty())
    {
        CKey local_privkey;
        local_privkey.Set(mRawLocalPrivKey.begin(), mRawLocalPrivKey.end(), true);
        CPubKey LocalPubkey = local_privkey.GetPubKey();
        local_pubkey_cache.assign(LocalPubkey.begin(), LocalPubkey.end());
    }

    return local_pubkey_cache;
}

}