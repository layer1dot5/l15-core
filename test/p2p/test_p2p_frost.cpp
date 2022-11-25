
#include <span>
#include <algorithm>

#include "smartinserter.hpp"


#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"

#include "wrapstream.hpp"

#include "util/strencodings.h"

#include "p2p_frost.hpp"
#include "wallet_api.hpp"
#include "random.h"


using namespace l15;
using namespace l15::p2p;

core::WalletApi w;

TEST_CASE("FrostMessage")
{
    l15::xonly_pubkey pk = ParseHex("11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF");
    FrostMessage m(FROST_MESSAGE::SIGNATURE_SHARE, move(pk));

    cex::stream<std::deque<uint8_t>> s;

    uint8_t etalon[] = {0, 1, 0, 4, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    CHECK_NOTHROW(m.Serialize(s));

    std::clog << l15::hex(s) << std::endl;

    size_t i = 0;
    for (auto elem: s) {
        CHECK((elem == etalon[i++]));
    }

    auto res = Unserialize(w.Secp256k1Context(), s);

    FrostMessage *m1 = nullptr;
    REQUIRE((m1 = dynamic_cast<FrostMessage *>(res.get())));

    CHECK((m.protocol_id == m1->protocol_id));
    CHECK((m.id == m1->id));
    CHECK((m.pubkey == m1->pubkey));
}

TEST_CASE("NonceCommitments")
{
    seckey nonce1, nonce2;
    do {
        GetStrongRandBytes(nonce1);
    } while (!secp256k1_ec_seckey_verify(w.Secp256k1Context(), nonce1.data()));
    do {
        GetStrongRandBytes(nonce2);
    } while (!secp256k1_ec_seckey_verify(w.Secp256k1Context(), nonce2.data()));

    secp256k1_pubkey pubnonce1;
    if (!secp256k1_ec_pubkey_create(w.Secp256k1Context(), &pubnonce1, nonce1.data())) {
        throw WrongKeyError();
    }
    secp256k1_pubkey pubnonce2;
    if (!secp256k1_ec_pubkey_create(w.Secp256k1Context(), &pubnonce2, nonce1.data())) {
        throw WrongKeyError();
    }

    secp256k1_frost_pubnonce pubnonce{{0x8b, 0xcf, 0xe2, 0xc2}};
    memcpy(pubnonce.data + 4, pubnonce1.data, 64);
    memcpy(pubnonce.data + 68, pubnonce2.data, 64);


    l15::xonly_pubkey pk = ParseHex("11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF");

    NonceCommitments m(move(pk));
    m.nonce_commitments.emplace_back(move(pubnonce));

    cex::stream<std::deque<uint8_t>> s;
    CHECK_NOTHROW(m.Serialize(w.Secp256k1Context(), s));

    std::clog << l15::hex(s) << std::endl;

    auto res = Unserialize(w.Secp256k1Context(), s);

    NonceCommitments *m1 = nullptr;
    REQUIRE((m1 = dynamic_cast<NonceCommitments *>(res.get())));

    CHECK((m.protocol_id == m1->protocol_id));
    CHECK((m.id == m1->id));
    CHECK((m.pubkey == m1->pubkey));
    CHECK((memcmp(m.nonce_commitments.front().data, m1->nonce_commitments.front().data, sizeof(secp256k1_frost_pubnonce::data))==0));
}

TEST_CASE("KeyShareCommitment")
{
    seckey sk1, sk2;
    do {
        GetStrongRandBytes(sk1);
    } while (!secp256k1_ec_seckey_verify(w.Secp256k1Context(), sk1.data()));
    do {
        GetStrongRandBytes(sk2);
    } while (!secp256k1_ec_seckey_verify(w.Secp256k1Context(), sk2.data()));

    secp256k1_pubkey pk1, pk2;
    if (!secp256k1_ec_pubkey_create(w.Secp256k1Context(), &pk1, sk1.data())) {
        throw WrongKeyError();
    }
    if (!secp256k1_ec_pubkey_create(w.Secp256k1Context(), &pk2, sk1.data())) {
        throw WrongKeyError();
    }

    l15::xonly_pubkey pk = ParseHex("11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF");

    KeyShareCommitment m(move(pk));
    m.share_commitment.emplace_back(move(pk1));
    m.share_commitment.emplace_back(move(pk2));

    cex::stream<std::deque<uint8_t>> s;
    CHECK_NOTHROW(m.Serialize(w.Secp256k1Context(), s));

    std::clog << l15::hex(s) << std::endl;

    auto res = Unserialize(w.Secp256k1Context(), s);

    KeyShareCommitment *m1 = nullptr;
    REQUIRE((m1 = dynamic_cast<KeyShareCommitment *>(res.get())));

    CHECK((m.protocol_id == m1->protocol_id));
    CHECK((m.id == m1->id));
    CHECK((m.pubkey == m1->pubkey));
    CHECK((memcmp(m.share_commitment[0].data, m1->share_commitment[0].data, sizeof(secp256k1_pubkey::data))==0));
    CHECK((memcmp(m.share_commitment[1].data, m1->share_commitment[1].data, sizeof(secp256k1_pubkey::data))==0));
}

TEST_CASE("KeyShareCommitment15")
{
    const size_t K = 30;

    std::vector<seckey> sk;
    sk.resize(K);

    std::for_each(sk.begin(), sk.end(), [](auto& k) {
        do {
            GetStrongRandBytes(k);
        } while (!secp256k1_ec_seckey_verify(w.Secp256k1Context(), k.data()));
    });

    std::vector<secp256k1_pubkey> pk;
    pk.resize(K);
    std::transform(sk.begin(), sk.end(), pk.begin(), [](auto& k)
    {
        secp256k1_pubkey p;
        if (!secp256k1_ec_pubkey_create(w.Secp256k1Context(), &p, k.data())) {
            throw WrongKeyError();
        }
        uint8_t buf[33];
        const size_t buflen = sizeof(buf);
        size_t outlen = buflen;
        if (!secp256k1_ec_pubkey_serialize(w.Secp256k1Context(), buf, &outlen, &p, SECP256K1_EC_COMPRESSED)) {
            throw std::runtime_error("FROST key share commitment serialize error 1");
        }
        std::clog << hex(buf) << std::endl;

        return p;
    });

    l15::xonly_pubkey pk0 = ParseHex("11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF");

    KeyShareCommitment m(move(pk0));
    m.share_commitment = move(pk);

    std::clog << std::endl;
    std::for_each(m.share_commitment.begin(), m.share_commitment.end(), [](auto& pk){
        uint8_t buf[33];
        const size_t buflen = sizeof(buf);
        size_t outlen = buflen;
        if (!secp256k1_ec_pubkey_serialize(w.Secp256k1Context(), buf, &outlen, &pk, SECP256K1_EC_COMPRESSED)) {
            throw std::runtime_error("FROST key share commitment serialize error 2");
        }
        std::clog << hex(buf) << std::endl;

    });
    std::clog << std::endl;

    cex::stream<std::deque<uint8_t>> s;
    CHECK_NOTHROW(m.Serialize(w.Secp256k1Context(), s));

    std::clog << l15::hex(s) << std::endl;

    std::shared_ptr<FrostMessage> res;
    CHECK_NOTHROW(res = Unserialize(w.Secp256k1Context(), s));

    KeyShareCommitment *m1 = nullptr;
    REQUIRE((m1 = dynamic_cast<KeyShareCommitment *>(res.get())));

    CHECK((m.protocol_id == m1->protocol_id));
    CHECK((m.id == m1->id));
    CHECK((m.pubkey == m1->pubkey));
    CHECK((memcmp(m.share_commitment[0].data, m1->share_commitment[0].data, sizeof(secp256k1_pubkey::data))==0));
    CHECK((memcmp(m.share_commitment[1].data, m1->share_commitment[1].data, sizeof(secp256k1_pubkey::data))==0));
    CHECK((memcmp(m.share_commitment[2].data, m1->share_commitment[2].data, sizeof(secp256k1_pubkey::data))==0));
    CHECK((memcmp(m.share_commitment[3].data, m1->share_commitment[3].data, sizeof(secp256k1_pubkey::data))==0));
    CHECK((memcmp(m.share_commitment[4].data, m1->share_commitment[4].data, sizeof(secp256k1_pubkey::data))==0));
    CHECK((memcmp(m.share_commitment[5].data, m1->share_commitment[5].data, sizeof(secp256k1_pubkey::data))==0));
    CHECK((memcmp(m.share_commitment[6].data, m1->share_commitment[6].data, sizeof(secp256k1_pubkey::data))==0));
    CHECK((memcmp(m.share_commitment[7].data, m1->share_commitment[7].data, sizeof(secp256k1_pubkey::data))==0));
    CHECK((memcmp(m.share_commitment[8].data, m1->share_commitment[8].data, sizeof(secp256k1_pubkey::data))==0));
    CHECK((memcmp(m.share_commitment[9].data, m1->share_commitment[9].data, sizeof(secp256k1_pubkey::data))==0));
    CHECK((memcmp(m.share_commitment[10].data, m1->share_commitment[10].data, sizeof(secp256k1_pubkey::data))==0));
    CHECK((memcmp(m.share_commitment[11].data, m1->share_commitment[11].data, sizeof(secp256k1_pubkey::data))==0));
    CHECK((memcmp(m.share_commitment[12].data, m1->share_commitment[12].data, sizeof(secp256k1_pubkey::data))==0));
    if (K>13) { CHECK((memcmp(m.share_commitment[13].data, m1->share_commitment[13].data, sizeof(secp256k1_pubkey::data))==0));}
    if (K>14) { CHECK((memcmp(m.share_commitment[14].data, m1->share_commitment[14].data, sizeof(secp256k1_pubkey::data))==0));}
    if (K>15) { CHECK((memcmp(m.share_commitment[15].data, m1->share_commitment[15].data, sizeof(secp256k1_pubkey::data))==0));}
    if (K>16) { CHECK((memcmp(m.share_commitment[16].data, m1->share_commitment[16].data, sizeof(secp256k1_pubkey::data))==0));}
    if (K>17) { CHECK((memcmp(m.share_commitment[17].data, m1->share_commitment[17].data, sizeof(secp256k1_pubkey::data))==0));}
    if (K>18) { CHECK((memcmp(m.share_commitment[18].data, m1->share_commitment[18].data, sizeof(secp256k1_pubkey::data))==0));}
    if (K>19) { CHECK((memcmp(m.share_commitment[19].data, m1->share_commitment[19].data, sizeof(secp256k1_pubkey::data))==0));}
    if (K>20) { CHECK((memcmp(m.share_commitment[20].data, m1->share_commitment[20].data, sizeof(secp256k1_pubkey::data))==0));}
    if (K>21) { CHECK((memcmp(m.share_commitment[21].data, m1->share_commitment[21].data, sizeof(secp256k1_pubkey::data))==0));}
    if (K>22) { CHECK((memcmp(m.share_commitment[22].data, m1->share_commitment[22].data, sizeof(secp256k1_pubkey::data))==0));}
    if (K>23) { CHECK((memcmp(m.share_commitment[23].data, m1->share_commitment[23].data, sizeof(secp256k1_pubkey::data))==0));}
    if (K>24) { CHECK((memcmp(m.share_commitment[24].data, m1->share_commitment[24].data, sizeof(secp256k1_pubkey::data))==0));}
    if (K>25) { CHECK((memcmp(m.share_commitment[25].data, m1->share_commitment[25].data, sizeof(secp256k1_pubkey::data))==0));}
    if (K>26) { CHECK((memcmp(m.share_commitment[26].data, m1->share_commitment[26].data, sizeof(secp256k1_pubkey::data))==0));}
    if (K>27) { CHECK((memcmp(m.share_commitment[27].data, m1->share_commitment[27].data, sizeof(secp256k1_pubkey::data))==0));}
    if (K>28) { CHECK((memcmp(m.share_commitment[28].data, m1->share_commitment[28].data, sizeof(secp256k1_pubkey::data))==0));}
    if (K>29) { CHECK((memcmp(m.share_commitment[29].data, m1->share_commitment[29].data, sizeof(secp256k1_pubkey::data))==0));}
}

TEST_CASE("KeyShare")
{
    l15::xonly_pubkey pk = ParseHex("11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF");
    KeyShare m(move(pk));
    std::transform(m.pubkey.crbegin(), m.pubkey.crend(), m.share.data, [](const auto v){return v;});

    cex::stream<std::deque<uint8_t>> s;

    uint8_t etalon[] = {0, 1, 0, 2, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                                    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
                                    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};

    CHECK_NOTHROW(m.Serialize(w.Secp256k1Context(), s));

    std::clog << l15::hex(s) << std::endl;

    size_t i = 0;
    for (auto elem: s) {
        CHECK((elem == etalon[i++]));
    }

    auto res = Unserialize(w.Secp256k1Context(), s);

    KeyShare *m1 = nullptr;
    REQUIRE((m1 = dynamic_cast<KeyShare *>(res.get())));

    CHECK(m.protocol_id == m1->protocol_id);
    CHECK(m.id == m1->id);
    CHECK((m.pubkey == m1->pubkey));
    CHECK(memcmp(m.share.data, m1->share.data, sizeof(secp256k1_frost_share::data))==0);
}

TEST_CASE("SignatureCommitment")
{
    l15::xonly_pubkey pk = ParseHex("11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF");
    SignatureCommitment m(move(pk), 0xabcdef);

    cex::stream<std::deque<uint8_t>> s;

    uint8_t etalon[] = {0, 1, 0, 3, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                        0x00, 0xab, 0xcd, 0xef};

    CHECK_NOTHROW(m.Serialize(w.Secp256k1Context(), s));

    std::clog << l15::hex(s) << std::endl;

    size_t i = 0;
    for (auto elem: s) {
        CHECK((elem == etalon[i++]));
    }

    auto res = Unserialize(w.Secp256k1Context(), s);

    SignatureCommitment *m1 = nullptr;
    REQUIRE((m1 = dynamic_cast<SignatureCommitment *>(res.get())));

    CHECK(m.protocol_id == m1->protocol_id);
    CHECK(m.id == m1->id);
    CHECK((m.pubkey == m1->pubkey));
    CHECK(m.operation_id == m1->operation_id);
}

TEST_CASE("SignatureShare")
{
    l15::xonly_pubkey pk = ParseHex("11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF");
    SignatureShare m(move(pk), 0xabcdef);
    std::transform(m.pubkey.crbegin(), m.pubkey.crend(), m.share.begin(), [](const auto v){return v;});

    cex::stream<std::deque<uint8_t>> s;

    uint8_t etalon[] = {0, 1, 0, 4, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                        0x00, 0xab, 0xcd, 0xef,
                        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
                        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};

    CHECK_NOTHROW(m.Serialize(w.Secp256k1Context(), s));

    std::clog << l15::hex(s) << std::endl;

    size_t i = 0;
    for (auto elem: s) {
        CHECK((elem == etalon[i++]));
    }

    auto res = Unserialize(w.Secp256k1Context(), s);

    SignatureShare *m1 = nullptr;
    REQUIRE((m1 = dynamic_cast<SignatureShare *>(res.get())));

    CHECK(m.protocol_id == m1->protocol_id);
    CHECK(m.id == m1->id);
    CHECK((m.pubkey == m1->pubkey));
    CHECK(m.operation_id == m1->operation_id);
    CHECK((m.share == m1->share));
}
