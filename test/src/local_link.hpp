#pragma once

#include "p2p/link.hpp"
#include "p2p/frost.hpp"
#include "core/signer_api.hpp"

namespace l15::p2p {

class LocalLink : public Link
{
    core::SignerApi& mSigner;
public:
    explicit LocalLink(core::SignerApi& signer) : mSigner(signer) {}

    void Send(const Message& m) override
    {
        mSigner.Accept(m);
    }
};

}