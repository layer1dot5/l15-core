#include <deque>

#include "wrapstream.hpp"

#include "univalue.h"
#include "streams.h"

#include "onchain_service.hpp"

namespace l15::onchain_service {


namespace {

const char* STOP_ADDR = "inproc://stop";//"tcp://127.0.0.1:19010";

}

void OnChainService::Stop()
{
    zmq::socket_t sock(*zmq_ctx, ZMQ_PUB);
    zmq::message_t stopmsg(STOP);

    //std::clog << "Stopping oc-chain service " << STOP_ADDR;

    sock.bind(STOP_ADDR);

    sock.send(stopmsg);

    mThread.join();

    sock.close();
}


void OnChainService::Start()
{
    std::string res = mChain->GetZMQNotifications();

    UniValue notifications_config;
    notifications_config.read(res);

    std::string addr;

    for (const auto& entry: notifications_config.getValues()) {
        if (entry["type"].getValStr() == "pubrawblock") {
            addr = entry["address"].getValStr();
            break;
        }
    }

    if (addr.empty()) {
        throw std::runtime_error("Node does not provide ZMQ notifications. Have you configured it with 'zmqpubhashblock' param?");
    }

    mThread = std::thread(&OnChainService::MainCycle, this, move(addr));
}


template<typename T>
cex::stream<std::deque<std::byte>>& operator>> (cex::stream<std::deque<std::byte>>& stream, T& obj) {
    ::Unserialize(stream, obj);
    return stream;
}

class SerializeSream : public cex::stream<std::deque<std::byte>>
{
public:
    int GetVersion() const
    { return 0; }
};

void OnChainService::MainCycle(std::string&& addr) // NOLINT(performance-unnecessary-value-param)
{
    zmq::socket_t sock(*zmq_ctx, zmq::socket_type::sub);
    sock.set(zmq::sockopt::subscribe, "");

    sock.connect(addr);
    sock.connect(STOP_ADDR);

    bool next_block = false;
    //cex::stream<std::deque<std::byte>> buffer;
    SerializeSream buffer;

    for (;;) {

        if (!next_block && !buffer.empty()) {
            CBlock block;
            block.Unserialize(buffer);
            buffer.clear();

            m_block_handler(block.GetBlockHeader());
            for (const CTransactionRef tx: block.vtx) {
                m_tx_handler(*tx);
            }
;        }

        zmq::message_t msg;
        auto len = sock.recv(msg, zmq::recv_flags::none);

        if (msg == zmq::message_t(STOP)) {
            break;
        }
        else if (msg == zmq::message_t(std::string("rawblock"))) {
            std::clog << ">>>> New block <<<<" << std::endl;
        }
        else {
             buffer.append(msg.data<uint8_t>(), msg.data<uint8_t>() + msg.size());
        }

        next_block = msg.more();
    }
}


}

