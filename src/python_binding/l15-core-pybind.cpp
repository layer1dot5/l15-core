#include "l15-core-pybind.hpp"

#include "channel_keys.hpp"

namespace py = pybind11;

class ChannelKeysImpl : public l15::core::ChannelKeys {
public:
    ChannelKeysImpl(l15::seckey sk) : l15::core::ChannelKeys(move(sk)) {}

    using ChannelKeys::GetLocalPrivKey;
    using ChannelKeys::GetLocalPubKey;
};


/*
PYBIND11_MODULE(l15_core, m) {
    py::class_<ChannelKeysImpl>(m, "ChannelKeys")
            .def(py::init<l15::seckey>())
            .def("getLocalPrivKey", &ChannelKeysImpl::GetLocalPrivKey)
            .def("getLocalPubKey", &ChannelKeysImpl::GetLocalPubKey);
}
*/
