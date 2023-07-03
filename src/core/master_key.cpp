#include "master_key.hpp"
#include "util/spanparsing.h"
#include "hmac_sha512.h"

namespace l15::core {

namespace {
    const unsigned char seed_hash_tag[] = {'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd'};
}

MasterKey::MasterKey(const secp256k1_context* ctx, const bytevector& seed) : m_ctx(ctx), mKey(), mChainCode()
{
    uint8_t vout[64];
    CHMAC_SHA512{seed_hash_tag, sizeof(seed_hash_tag)}.Write(seed.data(), seed.size()).Finalize(vout);
    mKey.assign(vout, vout + 32);
    memcpy(mChainCode.begin(), vout + 32, 32);
    memory_cleanse(vout, sizeof(vout));
}

MasterKey::MasterKey(const bytevector& seed) : m_ctx(ChannelKeys::GetStaticSecp256k1Context()), mKey(), mChainCode()
{
    uint8_t vout[64];
    CHMAC_SHA512{seed_hash_tag, sizeof(seed_hash_tag)}.Write(seed.data(), seed.size()).Finalize(vout);
    mKey.assign(vout, vout + 32);
    memcpy(mChainCode.begin(), vout + 32, 32);
    memory_cleanse(vout, sizeof(vout));
}

void MasterKey::DeriveSelf(uint32_t branch)
{
    uint8_t vout[64];

    try {
        if ((branch >> 31) == 0) {
            secp256k1_pubkey pubkey;

            if (!secp256k1_ec_pubkey_create(m_ctx, &pubkey, mKey.data())) {
                throw WrongKeyError();
            }
            size_t pubkeylen = 33;
            bytevector pubkeydata(pubkeylen);
            if (!secp256k1_ec_pubkey_serialize(m_ctx, pubkeydata.data(), &pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED)) {
                throw KeyError("Master pubkey ");
            }
            BIP32Hash(mChainCode, branch, *pubkeydata.begin(), pubkeydata.data() + 1, vout);
        }
        else {
            BIP32Hash(mChainCode, branch, 0, mKey.data(), vout);
        }

        memcpy(mChainCode.begin(), vout + 32, 32);

        if (!secp256k1_ec_seckey_tweak_add(m_ctx, mKey.data(), vout)) {
            throw KeyError("Derive tweak");
        }
    }
    catch(...) {
        memset(vout, 0, sizeof(vout));
        std::rethrow_exception(std::current_exception());
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
        throw KeyError("Derivation path");
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