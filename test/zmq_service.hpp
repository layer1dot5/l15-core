#pragma once
#include <string>
#include <unordered_map>

#include "common.hpp"
#include "zmq_context.hpp"
#include "p2p_link.hpp"

namespace l15 {

class ZmqService : public service::ZmqContextSingleton
{
public:
    typedef std::unordered_map<xonly_pubkey, std::string, l15::hash<xonly_pubkey>> peers_map;
private:
    peers_map m_peers;


public:
    ZmqService() = default;

    void AddPeer(xonly_pubkey&& pk, string&& addr)
    { m_peers.emplace(move(pk), move(addr));}

    const peers_map& GetPeersMap() const
    { return m_peers; }

    void BindAddress(const std::string& addr, p2p::link_handler h);

    void Publish(const p2p::Message& m) const;
    void Send(const xonly_pubkey& pk, const p2p::Message& m) const;
};


}
