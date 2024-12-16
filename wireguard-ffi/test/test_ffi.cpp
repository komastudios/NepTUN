#include "common.h"

#include "TestCommon.h"

#include <utility>
#include <optional>
#include <span>

struct PtrDeleter {
    void operator()(struct wireguard_tunnel *t) const
    {
        wireguard_tunnel_free(t);
    }
};

using TunnelHnd = std::unique_ptr<struct wireguard_tunnel, PtrDeleter>;
using ByteVec = std::vector<uint8_t>;
using ByteSpan = std::span<const uint8_t>;

struct StaticKey {
    struct wireguard_x25519_key key {};
};

struct PublicKey {
    struct wireguard_x25519_key key {};
};

struct PrivateKey {
    StaticKey priv {};
    PublicKey pub {};

    static PrivateKey Generate()
    {
        auto key = wireguard_x25519_secret_key();
        return { key, wireguard_x25519_public_key(key) };
    }
};

struct TunnelResult {
    struct wireguard_result res {};
    ByteVec data;
    void read(const uint8_t* src, size_t capa)
    {
        data.resize(res.size < capa ? res.size : capa);
        if (!data.empty())
            memcpy(data.data(), src, data.size());
    }
};

struct Tunnel {
    TunnelHnd hnd;
    PrivateKey key;
    PublicKey serverKey;

    std::array<uint8_t, MAX_WIREGUARD_PACKET_SIZE> buffer {};

    static Tunnel Create(const PrivateKey& key, const PublicKey& serverKey,
        const std::optional<StaticKey>& sharedKey, uint16_t keep_alive, uint32_t index)
    {
        return Tunnel {
            .hnd = TunnelHnd {wireguard_new_tunnel(&key.priv.key, &serverKey.key,
                sharedKey.has_value() ? &sharedKey->key : nullptr, keep_alive, index) },
            .key = key,
            .serverKey = serverKey
        };
    }

    TunnelResult forceHandshake()
    {
        TunnelResult r;
        r.res = wireguard_force_handshake(hnd.get(), buffer.data(), buffer.size());
        r.read(buffer.data(), buffer.size());
        return r;
    }

    static std::pair<bool, PublicKey> ParseHandshakeAnon(const PrivateKey& key, ByteSpan data)
    {
        PublicKey k {};
        int err = wireguard_parse_handshake_anon(&key.priv.key, &key.pub.key, data.data(), data.size(), &k.key);
        return std::make_pair(err == 0, k);
    }

    void close()
    {
        hnd.reset();
    }
};

namespace {

using ::testing::Eq;

TEST(Keys, GenerateAndRoundtrip)
{
    auto key = wireguard_x25519_secret_key();
    auto pubkey = wireguard_x25519_public_key(key);

    std::string keyBase64 { print_key(&key) };
    struct wireguard_x25519_key k {};
    EXPECT_EQ(load_key_base64(&k, keyBase64.c_str()), 0);
    EXPECT_EQ(keyBase64, print_key(&k));

    std::string pubkeyBase64 { print_key(&pubkey) };
    struct wireguard_x25519_key pubk {};
    EXPECT_EQ(load_key_base64(&pubk, pubkeyBase64.c_str()), 0);
    EXPECT_EQ(pubkeyBase64, print_key(&pubk));

    auto pubkd = wireguard_x25519_public_key(k);
    EXPECT_EQ(pubkeyBase64, print_key(&pubkd));
}

struct TunnelTest : testing::Test {
};

TEST_F(TunnelTest, CreateAndDestroy)
{
    auto key = PrivateKey::Generate();
    auto serverKey = PrivateKey::Generate();
    auto tunnel = Tunnel::Create(key, serverKey.pub, {}, 0, 0);
    EXPECT_TRUE(tunnel.hnd.get());

    tunnel.close();
    EXPECT_FALSE(tunnel.hnd.get());
}

TEST_F(TunnelTest, HandleAnonHandshake)
{
    auto key = PrivateKey::Generate();
    auto serverKey = PrivateKey::Generate();

    auto tunnel = Tunnel::Create(key, serverKey.pub, {}, 0, 0);
    EXPECT_TRUE(tunnel.hnd.get());

    auto r = tunnel.forceHandshake();
    EXPECT_EQ(r.res.op, WRITE_TO_NETWORK);
    auto msgHandshake = r.data;
    EXPECT_EQ(msgHandshake.size(), r.res.size);

    auto [success, peerKey] = Tunnel::ParseHandshakeAnon(serverKey, msgHandshake);
    EXPECT_TRUE(success);

    std::string expectedKey { print_key(&key.pub.key) };
    std::string parsedKey { print_key(&peerKey.key) };
    EXPECT_EQ(parsedKey, expectedKey);
}

struct TwoTunnelTest : TunnelTest
{
    PrivateKey keyA;
    PrivateKey keyB;
    std::optional<StaticKey> sharedKey;
    uint16_t keepAlive {};
    uint32_t index {};

    Tunnel tunnelA;
    Tunnel tunnelB;

    void SetUp() override
    {
        TunnelTest::SetUp();

        keyA = PrivateKey::Generate();
        keyB = PrivateKey::Generate();
    }

    void CreateTunnels()
    {
        tunnelA = Tunnel::Create(keyA, keyB.pub, sharedKey, keepAlive, index);
        tunnelB = Tunnel::Create(keyB, keyA.pub, sharedKey, keepAlive, index);
    }
};

TEST_F(TwoTunnelTest, CreateAndDestroy)
{
    CreateTunnels();


}

} // namespace
