#pragma once

#include "p2p/link.hpp"
#include "p2p/frost.hpp"
#include "core/signer_service.hpp"

namespace l15::p2p {

class LocalLink : public Link
{
    SignerService& mSigner;
public:
    explicit LocalLink(SignerService& signer) : mSigner(signer) {}

    void Send(const Message& m) override
    {
        mSigner.Accept(m);
    }
};

}