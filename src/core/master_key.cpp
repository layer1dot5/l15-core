#include "master_key.hpp"
#include "util/spanparsing.h"
#include "hmac_sha512.h"

namespace l15::core {

namespace {
    const unsigned char seed_hash_tag[] = {'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd'};
}

MasterKey::MasterKey(const secp256k1_context* ctx, const std::vector<std::byte>& seed) : m_ctx(ctx)
{
    std::vector<unsigned char, secure_allocator<unsigned char>> vout(64);
    CHMAC_SHA512{seed_hash_tag, sizeof(seed_hash_tag)}.Write(UCharCast(seed.data()), seed.size()).Finalize(vout.data());
    mKey.assign(vout.data(), vout.data() + 32);
    memcpy(mChainCode.begin(), vout.data() + 32, 32);
}

MasterKey::MasterKey(const std::vector<std::byte>& seed) : m_ctx(ChannelKeys::GetStaticSecp256k1Context())
{
    std::vector<unsigned char, secure_allocator<unsigned char>> vout(64);
    CHMAC_SHA512{seed_hash_tag, sizeof(seed_hash_tag)}.Write(UCharCast(seed.data()), seed.size()).Finalize(vout.data());
    mKey.assign(vout.data(), vout.data() + 32);
    memcpy(mChainCode.begin(), vout.data() + 32, 32);
}

void MasterKey::DeriveSelf(uint32_t branch)
{
    std::vector<unsigned char, secure_allocator<unsigned char>> vout(64);
    if ((branch >> 31) == 0) {

        secp256k1_pubkey pubkey;

        if (!secp256k1_ec_pubkey_create(m_ctx, &pubkey, mKey.data())) {
            throw KeyError();
        }
        size_t pubkeylen = 33;
        bytevector pubkeydata(pubkeylen);
        if (!secp256k1_ec_pubkey_serialize(m_ctx, pubkeydata.data(), &pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED)) {
            throw KeyError();
        }
        BIP32Hash(mChainCode, branch, *pubkeydata.begin(), pubkeydata.data()+1, vout.data());
    } else {
        BIP32Hash(mChainCode, branch, 0, mKey.data(), vout.data());
    }

    memcpy(mChainCode.begin(), vout.data()+32, 32);

    if (!secp256k1_ec_seckey_tweak_add(m_ctx, mKey.data(), vout.data())) {
        throw KeyError();
    }
}

ChannelKeys MasterKey::MakeKey(bool do_tweak)
{
    ChannelKeys res(m_ctx, mKey);

    if (do_tweak) {
        res.AddTapTweak();
    }

    return res;
}

ChannelKeys MasterKey::Derive(const string &path, bool for_script) const
{
    auto branches = spanparsing::Split(path, '/');

    BIP86Tweak do_tweak = for_script ? SUPPRESS : AUTO;

    if (branches.front()[0] != 'm' || branches.front().size() != 1) {
        throw KeyError();
    }
    branches.erase(branches.begin());

    std::vector<uint32_t> uint_branches;
    uint_branches.reserve(branches.size());

    for (const auto& branch: branches) {
        uint32_t index;
        if (branch[branch.size() - 1] == '\'') {
            //hardened
            auto conv_res = std::from_chars(branch.begin(), branch.end() - 1, index);
            if (conv_res.ec == std::errc::invalid_argument) {
                throw std::invalid_argument("Wrong hex string");
            }
            index += BIP32_HARDENED_KEY_LIMIT;
        }
        else {
            // non hardened
            auto conv_res = std::from_chars(branch.begin(), branch.end(), index);
            if (conv_res.ec == std::errc::invalid_argument) {
                throw std::invalid_argument("Wrong hex string");
            }
        }
        uint_branches.push_back(index);
    }
    return Derive(uint_branches, do_tweak);
}


} // l15::core