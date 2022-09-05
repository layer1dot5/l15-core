
#include "univalue.h"

#include "onchain_service.hpp"

#include "onchain_protocol.hpp"

namespace l15::chain_service {

namespace details {

std::optional<zmq::context_t> OnChainServiceBase::zmq_ctx;

}

namespace {

const char* STOP_ADDR = "inproc://stop";//"tcp://127.0.0.1:19010";

const std::string STOP("stop");

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
        if (entry["type"].getValStr() == "pubhashblock") {
            addr = entry["address"].getValStr();
            break;
        }
    }

    if (addr.empty()) {
        throw std::runtime_error("Node does not provide ZMQ notifications. Have you configured it with 'zmqpubhashblock' param?");
    }

    mThread = std::thread(&OnChainService::MainCycle, this, addr);

    //std::this_thread::sleep_for(std::chrono::seconds(3));
}

void OnChainService::MainCycle(std::string addr) // NOLINT(performance-unnecessary-value-param)
{
    //std::clog << "On-chain service starting: " << STOP_ADDR;

    zmq::socket_t sock(*zmq_ctx, zmq::socket_type::sub);
    sock.set(zmq::sockopt::subscribe, "");

    sock.connect(addr);
    sock.connect(STOP_ADDR);
    //std::clog << "done" << std::endl;

    for (;;) {

        zmq::message_t msg;
        sock.recv(msg, zmq::recv_flags::none);

        std::clog << "On-chain message" << std::endl;

        if (msg == zmq::message_t(std::string("stop"))) {
            break;
        }
        else {
            std::clog << msg.str() << std::endl;
        }


    }
}

void OnChainService::CommitNonces()
{

}


}

