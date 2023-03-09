#pragma once

#include <future>
#include <memory>
#include <map>
#include <mutex>

#include "async_result.hpp"

#include "common.hpp"
#include "signer_api.hpp"
#include "generic_service.hpp"

namespace l15 {


namespace signer_service {

class SignerService
{
    std::shared_ptr<service::GenericService> mBgService;

public:
    explicit SignerService(std::shared_ptr<service::GenericService> bgService) : mBgService(move(bgService)) {}

    void Accept(std::shared_ptr<core::SignerApi> ps, p2p::frost_message_ptr msg);

    template <std::derived_from<cex::async_result_base<void>> RES>
    void ProcessKeyShareCommitment(std::shared_ptr<core::SignerApi> signer, RES&& handler)
    {
        mBgService->Serve([bgService=mBgService,
                           ws=std::weak_ptr<core::SignerApi>(signer),
                           shared_handler=cex::shared_async_result<void>(handler.forward())]()mutable{
            try {
                if (auto ps = ws.lock()) {
                    ps->CommitKeyShares([bgService, shared_handler]()mutable{
                        bgService->Serve([shared_handler]()mutable{
                            try {
                                shared_handler();
                            }
                            catch(...) {
                                shared_handler.on_error();
                            }
                        });
                    });
                }
                else std::cerr << "Signer API destroyed" << std::endl; }
            catch (...) {
                shared_handler.on_error();
            }
        });

    }

    template <std::derived_from<cex::async_result_base<const xonly_pubkey&>> RES>
    void NegotiateKey(std::shared_ptr<core::SignerApi> signer, RES&& handler)
    {
        mBgService->Serve([bgService = mBgService,
                           ws = std::weak_ptr<core::SignerApi>(signer),
                           shared_handler=cex::shared_async_result<const xonly_pubkey&>(handler.forward())]() mutable {
            try {
                if (auto ps = ws.lock()) {
                    ps->DistributeKeyShares([bgService, ws, shared_handler]() mutable {
                        bgService->Serve([ws, shared_handler]() mutable {
                            auto ps(ws.lock());
                            if (ps) {
                                try {
                                    ps->AggregateKey();
                                    shared_handler(ps->GetAggregatedPubKey());
                                }
                                catch (...) {
                                    shared_handler.on_error();
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
                shared_handler.on_error();
            }
        });
    }

    template <std::derived_from<cex::async_result_base<void>> RES>
    void CommitSigNonces(std::shared_ptr<core::SignerApi> ps, size_t count, RES&& handler)
    {
        mBgService->Serve([ws = std::weak_ptr<core::SignerApi>(ps), count, handler=handler.forward()]() mutable{
            try {
                auto ps(ws.lock());
                if (ps) {
                    ps->CommitNonces(count);
                    handler();
                }
                else {
                    std::cerr << "Signer API destroyed" << std::endl;
                }
            }
            catch(...) {
                handler.on_error();
            }
        });
    }

    template <std::derived_from<cex::async_result_base<void>> RES>
    void ProcessSignatureCommitments(std::shared_ptr<core::SignerApi> ps, const scalar& message, const core::operation_id& opid, bool participate, RES&& handler)
    {
        auto ws = std::weak_ptr<core::SignerApi>(ps);
        mBgService->Serve([=, bgService = mBgService, handler = handler.forward()]() mutable {
            if (auto ps = ws.lock()) {
                ps->InitSignature(opid, core::make_moving_callable([=, handler = handler.forward()]() mutable {
                    bgService->Serve([=, handler = handler.forward()]() mutable {
                        try {
                            if (auto ps = ws.lock()) {
                                clog << "[" << hex(ps->GetLocalPubKey()).substr(0,8) << "] do PreprocessSignature" << std::endl;
                                ps->PreprocessSignature(message, opid);
                                handler();
                            }
                        }
                        catch (...) {
                            handler.on_error();
                        }
                    });
                }), [](){}, participate);
            }
        });
    }

    template <std::derived_from<cex::async_result_base<signature>> RES>
    void Sign(std::shared_ptr<core::SignerApi> ps, const core::operation_id& opid, RES&& handler)
    {
        auto ws = std::weak_ptr<core::SignerApi>(ps);
        auto shared_handler = cex::shared_async_result<signature>(handler.forward());
        mBgService->Serve([=, bgService = mBgService]() mutable {
            if (auto ps = ws.lock()) {
                try {
                    ps->DistributeSigShares(opid, [=]() mutable {
                        bgService->Serve([=, shared_handler = move(shared_handler)]() mutable {
                            if (auto ps = ws.lock()) {
                                try {
                                    shared_handler(ps->AggregateSignature(opid));
                                }
                                catch (...) {
                                    shared_handler.on_error();
                                }
                                ps->ClearSignatureCache(opid);
                            }
                        });
                    });
                }
                catch (...) {
                    shared_handler.on_error();
                }
            }
        });
    }

};

} // namespace signing_service
} // namespace l15
