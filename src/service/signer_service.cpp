
#include "signer_service.hpp"
#include "generic_service.hpp"

namespace l15::signer_service {

void SignerService::Accept(std::shared_ptr<core::SignerApi> ps, p2p::frost_message_ptr msg)
{
    ps->Accept(*msg);

    //mBgService->Serve([=](){ ps->Accept(*msg); });
}

void SignerService::PublishKeyShareCommitment(std::shared_ptr<core::SignerApi> ps,
                                              std::function<void()>&& on_complete,
                                              std::function<void()>&& on_error)
{
    mBgService->Serve([ws = std::weak_ptr<core::SignerApi>(ps), on_complete = move(on_complete), on_error = move(on_error)]() {
        try {
            auto ps(ws.lock());
            if (ps) {
                ps->CommitKeyShares();
                on_complete();
            }
            else {
                std::cerr << "Signer API destroyed" << std::endl;
            }
        }
        catch (...) {
            on_error();
        }
    });
}

void SignerService::NegotiateKey(std::shared_ptr<core::SignerApi> ps,
                                 std::function<void(const xonly_pubkey&)>&& on_complete,
                                 std::function<void()>&& on_error)
{
    mBgService->Serve([bgService = mBgService, ws = std::weak_ptr<core::SignerApi>(ps), on_complete = move(on_complete), on_error = move(on_error)]() {
        try {
            auto ps(ws.lock());
            if (ps) {
                ps->DistributeKeyShares([bgService, ws, on_complete, on_error]() {
                    bgService->Serve([ws, on_complete, on_error]() {
                        auto ps(ws.lock());
                        if (ps) {
                            try {
                                ps->AggregateKey();
                                on_complete(ps->GetAggregatedPubKey());
                            }
                            catch (...) {
                                on_error();
                            }
                        }
                        else {
                            std::cerr << "Signer API destroyed" << std::endl;
                        }
                    });
                });
            }
            else {
                std::cerr << "Signer API destroyed" << std::endl;
            }
        }
        catch (...) {
            on_error();
        }
    });
}

void SignerService::PublishNonces(std::shared_ptr<core::SignerApi> ps, size_t count,
                                               std::function<void()>&& on_complete,
                                               std::function<void()>&& on_error)
{
    mBgService->Serve([ws = std::weak_ptr<core::SignerApi>(ps), count, on_complete = move(on_complete), on_error = move(on_error)]() {
        try {
            auto ps(ws.lock());
            if (ps) {
                ps->CommitNonces(count);
                on_complete();
            }
            else {
                std::cerr << "Signer API destroyed" << std::endl;
            }
        }
        catch(...) {
            on_error();
        }
    });
}

void SignerService::Sign(std::shared_ptr<core::SignerApi> ps, const uint256 &message, core::operation_id opid,
                         std::function<void(signature)>&& on_complete,
                         std::function<void()>&& on_error)
{
    mBgService->Serve([ws = std::weak_ptr<core::SignerApi>(ps), message, opid, on_complete = move(on_complete), on_error = move(on_error)]() {

        auto ps(ws.lock());
        if (ps) {
            ps->InitSignature(opid, core::make_moving_callable([=]() {
                try {
                    auto ps(ws.lock());
                    if (ps) {
                        ps->PreprocessSignature(message, opid);
                        ps->DistributeSigShares(opid);
                    }
                }
                catch (...) {
                    on_error();
                }
            }), core::make_moving_callable([=]() {
                auto ps(ws.lock());
                if (ps) {
                    try {
                        on_complete(ps->AggregateSignature(opid));
                    }
                    catch (...) {
                        on_error();
                    }
                    ps->ClearSignatureCache(opid);
                }
            }));
        }
    });
}


} // l15