#include "l15-core-pybind.hpp"

#include "channel_keys.hpp"

secp256k1_context* ChannelKeysImpl::ctx = nullptr;

secp256k1_context* ChannelKeysImpl::GetSecp256k1Context() {
    if (ctx == nullptr) {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);
        std::vector<unsigned char/*, secure_allocator<unsigned char>*/> vseed(32);
        GetRandBytes(vseed);
        int ret = secp256k1_context_randomize(ctx, vseed.data());
        assert(ret);
    }
    return ctx;
}
/*
PYBIND11_MODULE(l15_core, m) {
    py::class_<ChannelKeysImpl>(m, "ChannelKeys")
            .def(py::init<l15::seckey>())
            .def("getLocalPrivKey", &ChannelKeysImpl::GetLocalPrivKey)
            .def("getLocalPubKey", &ChannelKeysImpl::GetLocalPubKey);
}
*/
