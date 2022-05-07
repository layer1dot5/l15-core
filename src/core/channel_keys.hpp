#pragma once

#include <vector>

#include "script/script.h"

namespace l15 {

class ChannelKeys
{
    vector<uint8_t> mRawLocalPrivKey;
    vector<uint8_t> mRawRemotePubKey;
public:
    ChannelKeys(vector<uint8_t> &&localkey, vector<uint8_t> &&remotepubkey)
            : mRawLocalPrivKey(std::move(localkey)), mRawRemotePubKey(remotepubkey)
    {}

    ChannelKeys(ChannelKeys &&old) noexcept
            : mRawLocalPrivKey(std::move(old.mRawLocalPrivKey)), mRawRemotePubKey(std::move(old.mRawRemotePubKey))
    {}

    ChannelKeys& operator=(const ChannelKeys& ) = delete;
    ChannelKeys& operator=(ChannelKeys&& ) = delete;

    CScript MakeMultiSigScript() const;

    const bytevector &RawLocalPrivKey() const
    { return mRawLocalPrivKey; }

    const bytevector &RawLocalPubKey() const;

    const bytevector &RawRemotePubKey() const
    { return mRawRemotePubKey; }
};

}
