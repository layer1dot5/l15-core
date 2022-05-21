#pragma once

#include "channel.hpp"
#include "channel_keys.hpp"
#include "wallet_api.hpp"
#include "chain_api.hpp"

struct ChannelWrapper
{
    l15::channel_ptr mChannelForAliceSide;
    l15::channel_ptr mChannelForCarolSide;

    void open_channel(l15::api::ChainApi& api)
    {
        l15::ChannelKeys alice_sk(api.Wallet());
        l15::ChannelKeys carol_sk(api.Wallet());

        alice_sk.SetRemotePubKeys({carol_sk.GetLocalPubKey()});
        carol_sk.SetRemotePubKeys({alice_sk.GetLocalPubKey()});

        std::string alice_ret_addr = api.GetNewAddress("Alice Return");
        std::string carol_ret_addr = api.GetNewAddress("Carol Return");
    }

    void close_channel()
    {

    }

    l15::Channel& channel_for_alice() { return *mChannelForAliceSide; }
    l15::Channel& channel_for_carol() { return *mChannelForCarolSide; }

};